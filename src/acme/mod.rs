use async_trait::async_trait;
use generic_async_http_client::{Error as HTTPError, Request, Response};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    path::{Path, PathBuf},
};
use thiserror::Error;

mod account;
pub use account::Account;

use crate::{
    crypto::sha256_hasher,
    fs::{read_if_exist, write, write_file},
};

pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

/// An ACME directory. Containing the REST endpoints of an ACME provider
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

impl Directory {
    pub async fn discover(url: &str) -> Result<Self, AcmeError> {
        Ok(Request::get(url).exec().await?.json().await?)
    }
    pub async fn nonce(&self) -> Result<String, AcmeError> {
        let response = Request::get(self.new_nonce.as_str()).exec().await?;
        get_header(&response, "replay-nonce")
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Order {
    Pending {
        authorizations: Vec<String>,
        finalize: String,
    },
    Ready {
        finalize: String,
    },
    Valid {
        certificate: String,
    },
    Invalid,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Auth {
    Pending {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    Valid,
    Invalid,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    pub url: String,
    pub token: String,
}

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http request error: {0}")]
    HttpRequest(#[from] HTTPError),
    #[error("acme service response is missing {0} header")]
    MissingHeader(&'static str),
    #[error("no tls-alpn-01 challenge found")]
    NoTlsAlpn01Challenge,
    #[error("HTTP Status {0} indicates error")]
    HttpStatus(u16),
    #[cfg(feature = "use_rustls")]
    #[error("Could not create Certificate: {0}")]
    RcgenError(#[from] rcgen::RcgenError),
    #[error("error from cache: {0}")]
    Cache(Box<dyn AnyError>),
}

impl AcmeError {
    pub fn cache<E: AnyError>(err: E) -> Self {
        Self::Cache(Box::new(err))
    }
}

/// parse a HTTP header as String or fail
fn get_header(response: &Response, header: &'static str) -> Result<String, AcmeError> {
    response
        .header(header)
        .and_then(|hv| hv.try_into().ok())
        .ok_or(AcmeError::MissingHeader(header))
}

#[async_trait]
pub trait AcmeCache {
    type Error: AnyError;

    async fn read_account(&self, contacts: &[&str]) -> Result<Option<Vec<u8>>, Self::Error>;

    async fn write_account(&self, contacts: &[&str], contents: &[u8]) -> Result<(), Self::Error>;

    async fn write_certificate(
        &self,
        domains: &[String],
        directory_url: &str,
        key_pem: &str,
        certificate_pem: &str,
    ) -> Result<(), Self::Error>;
}

macro_rules! impl_path_cache {
    ($type:ident) => {
        #[async_trait]
        impl AcmeCache for $type {
            type Error = std::io::Error;

            async fn read_account(
                &self,
                contacts: &[&str],
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                read_if_exist(self, Account::cached_key_file_name(contacts)).await
            }

            async fn write_account(
                &self,
                contacts: &[&str],
                contents: &[u8],
            ) -> Result<(), Self::Error> {
                write_file(self, Account::cached_key_file_name(contacts), contents).await
            }

            async fn write_certificate(
                &self,
                domains: &[String],
                directory_url: &str,
                key_pem: &str,
                certificate_pem: &str,
            ) -> Result<(), Self::Error> {
                let hash = {
                    let mut ctx = sha256_hasher();
                    for domain in domains {
                        ctx.update(domain.as_ref());
                        ctx.update(&[0])
                    }
                    // cache is specific to a particular ACME API URL
                    ctx.update(directory_url.as_bytes());
                    base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD)
                };
                let file = AsRef::<Path>::as_ref(self).join(&format!("cached_cert_{}", hash));
                let content = format!("{}\n{}", key_pem, certificate_pem);
                write(&file, &content).await?;
                Ok(())
            }
        }
    };
}

impl_path_cache!(PathBuf);
impl_path_cache!(Path);
impl_path_cache!(String);
impl_path_cache!(str);

pub trait AnyError: std::error::Error + Send + Sync + 'static {}

impl<T> AnyError for T where T: std::error::Error + Send + Sync + 'static {}
