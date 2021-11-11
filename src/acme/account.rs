/*!
An ACME Account

1. `load_or_create` your Account
2. place a `new_order` for your domains
3. `check_auth` for a single domain, if valid move to 6.
4. use `tls_alpn_01` to get a certificate for it
5. `trigger_challenge` on that domain
6. repeat 3. - 5. for all other domains
7. `send_csr` for your cert ...
8. ... and finally `obtain_certificate`

*/

use base64::URL_SAFE_NO_PAD;

use serde_json::json;

use crate::{
    acme::{
        get_header, AcmeCache, AcmeError, Auth, Challenge, ChallengeType, Directory, Identifier,
        Order,
    },
    crypto::{sha256_hasher, EcdsaP256SHA256KeyPair},
    jose::{jose_req, key_authorization_sha256},
};
use generic_async_http_client::Response;

#[derive(Debug)]
pub struct Account {
    key_pair: EcdsaP256SHA256KeyPair,
    directory: Directory,
    kid: String,
}

impl Account {
    /// Create or load a cached Account for ACME provider at `directory`.
    /// Provide your email in `contact` in the form *mailto:admin@example.com* to receive warnings regarding your certificate.
    /// Set a `cache` to remember/load your account.
    pub async fn load_or_create<'a, C, S, I>(
        directory: Directory,
        cache: Option<&C>,
        contact: I,
    ) -> Result<Self, AcmeError>
    where
        C: AcmeCache,
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();
        let pkcs8 = match &cache {
            Some(cache) => cache
                .read_account(&contact)
                .await
                .map_err(AcmeError::cache)?,
            None => None,
        };
        let key_pair = match pkcs8 {
            Some(pkcs8) => {
                log::info!("found cached account key");
                EcdsaP256SHA256KeyPair::load(&pkcs8)
            }
            None => {
                log::info!("creating a new account key");
                match EcdsaP256SHA256KeyPair::generate() {
                    Ok(pkcs8) => {
                        let data = pkcs8.as_ref();
                        if let Some(cache) = &cache {
                            cache
                                .write_account(&contact, data)
                                .await
                                .map_err(AcmeError::cache)?;
                        }
                        EcdsaP256SHA256KeyPair::load(data)
                    }
                    Err(_) => Err(()),
                }
            }
        }
        .map_err(|_| {
            AcmeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "could not create key pair",
            ))
        })?;
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": contact,
        })
        .to_string();
        let response = jose_req(
            &key_pair,
            None,
            &directory.nonce().await?,
            &directory.new_account,
            &payload,
        )
        .await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
        })
    }
    pub(crate) fn cached_key_file_name(contact: &[&str]) -> String {
        let mut ctx = sha256_hasher();
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
        format!("cached_account_{}", hash)
    }
    /// send a JOSE request using the own Key to sign it
    async fn request(&self, url: impl AsRef<str>, payload: &str) -> Result<Response, AcmeError> {
        jose_req(
            &self.key_pair,
            Some(&self.kid),
            &self.directory.nonce().await?,
            url.as_ref(),
            payload,
        )
        .await
    }
    /// send a new order for the DNS identifiers in domains
    pub async fn new_order(&self, domains: Vec<String>) -> Result<Order, AcmeError> {
        let domains: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let mut response = self.request(&self.directory.new_order, &payload).await?;
        Ok(response.json().await?)
    }
    /// check the authentication status for a particular challange
    pub async fn check_auth(&self, url: impl AsRef<str>) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let mut response = self.request(url, &payload).await?;
        Ok(response.json().await?)
    }
    /// trigger a particular challange
    pub async fn trigger_challenge(&self, url: impl AsRef<str>) -> Result<(), AcmeError> {
        self.request(&url, "{}").await?;
        Ok(())
    }
    /// request a certificate to be signed
    pub async fn send_csr(&self, url: impl AsRef<str>, csr: Vec<u8>) -> Result<Order, AcmeError> {
        let payload = format!(
            "{{\"csr\":\"{}\"}}",
            base64::encode_config(csr, URL_SAFE_NO_PAD)
        );
        let mut response = self.request(&url, &payload).await?;
        Ok(response.json().await?)
    }
    /// obtain a signed certificate for a privious CSR
    pub async fn obtain_certificate(&self, url: impl AsRef<str>) -> Result<String, AcmeError> {
        Ok(self.request(&url, "").await?.text().await?)
    }
    /// return a hash for first alpn challange.
    /// the hash needs to be presented inside the TLS certificate when the ACME TLS ALPN is present
    pub fn tls_alpn_01<'a>(
        &self,
        challenges: &'a [Challenge],
    ) -> Result<(&'a Challenge, impl AsRef<[u8]>), AcmeError> {
        let challenge = challenges
            .iter()
            .find(|c| c.typ == ChallengeType::TlsAlpn01);
        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let key_auth = key_authorization_sha256(&self.key_pair, &*challenge.token)?;

        Ok((challenge, key_auth))
    }
}
