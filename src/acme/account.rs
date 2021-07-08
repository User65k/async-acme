use base64::URL_SAFE_NO_PAD;

use serde_json::json; 

use crate::jose::{jose_req, key_authorization_sha256};
use crate::acme::{AcmeError, ChallengeType, Directory, get_header, Order, Identifier, Auth, Challenge};
use generic_async_http_client::{Response};
use crate::crypto::{EcdsaP256SHA256KeyPair, sha256_hasher};
use std::path::{PathBuf, Path};
use crate::fs::{create_dir_all, read_if_exist, write_file};

#[derive(Debug)]
pub struct Account {
    key_pair: EcdsaP256SHA256KeyPair,
    directory: Directory,
    cache: Option<PathBuf>,
    kid: String,
}

impl Account {
    /// contact is mailto:admin@yoursite.tld
    pub async fn load_or_create<'a, P, S, I>(
        directory: Directory,
        cache_dir: Option<P>,
        contact: I,
    ) -> Result<Self, AcmeError>
    where
        P: AsRef<Path>,
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        if let Some(cache_dir) = &cache_dir {
            create_dir_all(cache_dir).await?;
        }
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();
        let file = Self::cached_key_file_name(&contact);
        let pkcs8 = match &cache_dir {
            Some(cache_dir) => read_if_exist(cache_dir, &file).await?,
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
                        if let Some(cache_dir) = &cache_dir {
                            write_file(cache_dir, &file, data).await?;
                        }
                        EcdsaP256SHA256KeyPair::load(data)
                    },
                    Err(_) => Err(())
                }
            }
        }.map_err(|_|AcmeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "could not create key pair")))?;
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
        ).await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
            cache: cache_dir.map(|p| p.as_ref().to_path_buf()),
        })
    }
    fn cached_key_file_name(contact: &Vec<&str>) -> String {
        let mut ctx = sha256_hasher();
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
        format!("cached_account_{}", hash)
    }
    async fn request(&self, url: impl AsRef<str>, payload: &str) -> Result<Response, AcmeError> {
        jose_req(
            &self.key_pair,
            Some(&self.kid),
            &self.directory.nonce().await?,
            url.as_ref(),
            payload,
        ).await
    }
    pub async fn new_order(&self, domains: Vec<String>) -> Result<Order, AcmeError> {
        let domains: Vec<Identifier> = domains.into_iter().map(|d| Identifier::Dns(d)).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let mut response = self.request(&self.directory.new_order, &payload).await?;
        Ok(response.json().await?)
    }
    pub async fn auth(&self, url: impl AsRef<str>) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let mut response = self.request(url, &payload).await?;
        Ok(response.json().await?)
    }
    pub async fn challenge(&self, url: impl AsRef<str>) -> Result<(), AcmeError> {
        self.request(&url, "{}").await?;
        Ok(())
    }
    pub async fn finalize(&self, url: impl AsRef<str>, csr: Vec<u8>) -> Result<Order, AcmeError> {
        let payload = format!(
            "{{\"csr\":\"{}\"}}",
            base64::encode_config(csr, URL_SAFE_NO_PAD)
        );
        let mut response = self.request(&url, &payload).await?;
        Ok(response.json().await?)
    }
    pub async fn certificate(&self, url: impl AsRef<str>) -> Result<String, AcmeError> {
        Ok(self.request(&url, "").await?.text().await?)
    }
    /// return hash for first alpn challange
    pub fn tls_alpn_01<'a>(
        &self,
        challenges: &'a Vec<Challenge>,
    ) -> Result<(&'a Challenge, impl AsRef<[u8]>), AcmeError> {
        let challenge = challenges
            .iter()
            .filter(|c| c.typ == ChallengeType::TlsAlpn01)
            .next();
        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let key_auth = key_authorization_sha256(&self.key_pair, &*challenge.token)?;

        Ok((challenge, key_auth))
    }
}