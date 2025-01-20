/*! utilities to help with rustls.

```
use async_acme::{
    acme::LETS_ENCRYPT_STAGING_DIRECTORY,
    rustls_helper::order,
};
async fn get_new_cert(){
    let cache = "./cachedir/".to_string();
    let new_cert = order(
        |_sni, _cert| Ok(()),
        LETS_ENCRYPT_STAGING_DIRECTORY,
        &vec!["example.com".to_string()],
        Some(&cache),
        &vec!["mailto:admin@example.com".to_string()],
    )
    .await
    .unwrap();
}
```

*/

use futures_util::future::try_join_all;
use rustls::sign::CertifiedKey;
use std::time::Duration;
use thiserror::Error;

use crate::{
    acme::{Account, AcmeError, Auth, Directory, Identifier, Order},
    cache::AcmeCache,
    crypto::{gen_acme_cert, get_cert_duration_left, CertBuilder},
};

#[cfg(feature = "use_async_std")]
use async_std::task::sleep;
#[cfg(feature = "use_tokio")]
use tokio::time::sleep;

/// Obtain a signed certificate from the ACME provider at `directory_url` for the DNS `domains`.
///
/// The secret for the challenge is passed as a ready to use certificate to `set_auth_key(domain, certificate)?`.
/// This certificate has to be presented upon a TLS request with ACME ALPN and SNI for that domain.
///
/// Provide your email in `contact` in the form *mailto:admin@example.com* to receive warnings regarding your certificate.
/// Set a `cache` to remember your account.
pub async fn order<C, F>(
    set_auth_key: F,
    directory_url: &str,
    domains: &[String],
    cache: Option<&C>,
    contact: &[String],
) -> Result<CertifiedKey, OrderError>
where
    C: AcmeCache,
    F: Fn(String, CertifiedKey) -> Result<(), AcmeError>,
{
    let directory = Directory::discover(directory_url).await?;
    let account = Account::load_or_create(directory, cache, contact).await?;

    let (c, key_pem, cert_pem) = drive_order(set_auth_key, domains.to_vec(), account).await?;

    if let Some(dir) = cache {
        dir.write_certificate(domains, directory_url, &key_pem, &cert_pem)
            .await
            .map_err(AcmeError::cache)?;
    };
    Ok(c)
}

/// Obtain a signed certificate for the DNS `domains` using `account`.
///
/// The secret for the challenge is passed as a ready to use certificate to `set_auth_key(domain, certificate)?`.
/// This certificate has to be presented upon a TLS request with ACME ALPN and SNI for that domain.
///
/// Returns the signed Certificate, its private key as pem, and the certificate as pem again
pub async fn drive_order<F>(
    set_auth_key: F,
    domains: Vec<String>,
    account: Account,
) -> Result<(CertifiedKey, String, String), OrderError>
where
    F: Fn(String, CertifiedKey) -> Result<(), AcmeError>,
{
    let cert = CertBuilder::gen_new(domains.clone())?;
    let mut order = account.new_order(domains).await?;
    loop {
        order = match order {
            Order::Pending {
                authorizations,
                finalize,
            } => {
                let auth_futures = authorizations
                    .iter()
                    .map(|url| authorize(&set_auth_key, &account, url));
                try_join_all(auth_futures).await?;
                log::info!("completed all authorizations");
                Order::Ready { finalize }
            }
            Order::Ready { finalize } => {
                log::info!("sending csr");
                let csr = cert.get_csr()?;
                account.send_csr(finalize, csr).await?
            }
            Order::Valid { certificate } => {
                log::info!("download certificate");
                let acme_cert_pem = account.obtain_certificate(certificate).await?;
                let rd = acme_cert_pem.as_bytes();
                let pkey_pem = cert.private_key_as_pem_pkcs8();
                let cert_key = cert.sign(rd).map_err(|_| {
                    AcmeError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "could not parse certificate",
                    ))
                })?;
                return Ok((cert_key, pkey_pem, acme_cert_pem));
            }
            Order::Invalid => return Err(OrderError::BadOrder(order)),
        }
    }
}
async fn authorize<F>(set_auth_key: &F, account: &Account, url: &str) -> Result<(), OrderError>
where
    F: Fn(String, CertifiedKey) -> Result<(), AcmeError>,
{
    let (domain, challenge_url) = match account.check_auth(url).await? {
        Auth::Pending {
            identifier,
            challenges,
        } => {
            let Identifier::Dns(domain) = identifier;
            log::info!("trigger challenge for {}", &domain);
            let (challenge, key_auth) = account.tls_alpn_01(&challenges)?;
            let auth_key = gen_acme_cert(vec![domain.clone()], key_auth.as_ref())?;
            set_auth_key(domain.clone(), auth_key)?;
            account.trigger_challenge(&challenge.url).await?;
            (domain, challenge.url.clone())
        }
        Auth::Valid => return Ok(()),
        auth => return Err(OrderError::BadAuth(auth)),
    };
    for i in 0u8..5 {
        sleep(Duration::from_secs(1u64 << i)).await;
        match account.check_auth(url).await? {
            Auth::Pending { .. } => {
                log::info!("authorization for {} still pending", &domain);
                account.trigger_challenge(&challenge_url).await?
            }
            Auth::Valid => return Ok(()),
            auth => return Err(OrderError::BadAuth(auth)),
        }
    }
    Err(OrderError::TooManyAttemptsAuth(domain))
}

/// get the duration until the next ACME refresh should be done
pub fn duration_until_renewal_attempt(cert_key: Option<&CertifiedKey>, err_cnt: usize) -> Duration {
    let valid_until = cert_key
        .and_then(|cert_key| cert_key.cert.first())
        .and_then(|cert| get_cert_duration_left(cert).ok())
        .unwrap_or_default();

    let wait_secs = valid_until / 2;
    match err_cnt {
        0 => wait_secs,
        err_cnt => wait_secs.max(Duration::from_secs(1 << err_cnt)),
    }
}

#[derive(Error, Debug)]
pub enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
}
