use generic_async_http_client::{Error as HTTPError, Request, Response};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use thiserror::Error;
mod account;
pub use account::Account;

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
        Ok(Request::get(&url).exec().await?.json().await?)
    }
    pub async fn nonce(&self) -> Result<String, AcmeError> {
        let response = Request::get(&self.new_nonce.as_str()).exec().await?;
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
}

/// parse a HTTP header as String or fail
fn get_header(response: &Response, header: &'static str) -> Result<String, AcmeError> {
    response
        .header(header)
        .and_then(|hv| hv.try_into().ok())
        .ok_or_else(|| AcmeError::MissingHeader(header))
}
