
use std::time::Duration;
use std::path::Path;
use thiserror::Error;
use futures_util::future::try_join_all;

use rustls::sign::CertifiedKey;
use crate::crypto::{get_cert_duration_left, CertBuilder, gen_acme_cert};
use crate::acme::{Order, Directory, Account, Auth, Identifier, AcmeError};

#[cfg(feature = "use_async_std")]
use async_std::task::sleep;
#[cfg(feature = "use_tokio")]
use tokio::time::sleep;

pub async fn order<P, F>(
    set_auth_key: F,
    directory_url: &str,
    domains: &Vec<String>,
    cache_dir: Option<P>,
    contact: &Vec<String>,
) -> Result<CertifiedKey, OrderError>
where P: AsRef<Path>, F: Fn(String, CertifiedKey) -> Result<(), AcmeError>
{
    let cert = CertBuilder::gen_new(domains.clone())?;
    
    let directory = Directory::discover(&directory_url).await?;
    let account = Account::load_or_create(directory, cache_dir, contact).await?;
    let mut order = account.new_order(domains.clone()).await?;
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
                account.finalize(finalize, csr).await?
            }
            Order::Valid { certificate } => {
                log::info!("download certificate");
                let acme_cert_pem = account.certificate(certificate).await?;
                let rd = acme_cert_pem.as_bytes();
                let cert_key = cert.sign(rd)
                    .map_err(|_|AcmeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "could not parse certificate")))?;
                return Ok(cert_key);
            }
            Order::Invalid => return Err(OrderError::BadOrder(order)),
        }
    }
}
async fn authorize<F>(
    set_auth_key: &F,
    account: &Account,
    url: &String) -> Result<(), OrderError>
 where F: Fn(String, CertifiedKey) -> Result<(), AcmeError>
    {
    let (domain, challenge_url) = match account.auth(url).await? {
        Auth::Pending {
            identifier,
            challenges,
        } => {
            let Identifier::Dns(domain) = identifier;
            log::info!("trigger challenge for {}", &domain);
            let (challenge, key_auth) = account.tls_alpn_01(&challenges)?;
            let auth_key = gen_acme_cert(vec![domain.clone()], key_auth.as_ref())?;
            set_auth_key(domain.clone(), auth_key)?;
            account.challenge(&challenge.url).await?;
            (domain, challenge.url.clone())
        }
        Auth::Valid => return Ok(()),
        auth => return Err(OrderError::BadAuth(auth)),
    };
    for i in 0u8..5 {
        sleep(Duration::from_secs(1u64 << i)).await;
        match account.auth(url).await? {
            Auth::Pending { .. } => {
                log::info!("authorization for {} still pending", &domain);
                account.challenge(&challenge_url).await?
            }
            Auth::Valid => return Ok(()),
            auth => return Err(OrderError::BadAuth(auth)),
        }
    }
    Err(OrderError::TooManyAttemptsAuth(domain))
}

pub fn duration_until_renewal_attempt(cert_key: Option<&CertifiedKey>, err_cnt: usize) -> Duration {
    let valid_until = cert_key
        .and_then(|cert_key| cert_key.cert.first())
        .and_then(|cert| get_cert_duration_left(cert.0.as_slice()).ok())
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
    #[cfg(feature = "use_rustls")]
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::RcgenError),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
}