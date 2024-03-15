/*! Automatic Certificate Management Environment (ACME) acording to [rfc8555](https://datatracker.ietf.org/doc/html/rfc8555)

*/
use generic_async_http_client::{Error as HTTPError, Request, Response};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use thiserror::Error;

mod account;
pub use account::Account;

use crate::cache::CacheError;

/// URI of <https://letsencrypt.org/> staging Directory. Use this for tests. See <https://letsencrypt.org/docs/staging-environment/>
pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
/// URI of <https://letsencrypt.org/> prod Directory. Certificates aquired from this are trusted by most Browsers.
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
/// ALPN string used by ACME-TLS challanges
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
    ///query the endpoints from a discovery url
    pub async fn discover(url: &str) -> Result<Self, AcmeError> {
        Ok(Request::get(url).exec().await?.json().await?)
    }
    pub async fn nonce(&self) -> Result<String, AcmeError> {
        let response = Request::get(self.new_nonce.as_str()).exec().await?;
        get_header(&response, "replay-nonce")
    }
}

/// Challange used to prove ownership over a domain
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// State of an ACME request
#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Order {
    /// [`Auth`] for authorizations must be completed
    Pending {
        /// URLs for ([`Account::check_auth`](./struct.Account.html#method.check_auth))
        authorizations: Vec<String>,
        /// URL to send CSR to
        finalize: String,
    },
    /// [`Auth`] is done. CSR can be sent ([`Account::send_csr`](./struct.Account.html#method.send_csr))
    Ready {
        /// URL to send CSR to
        finalize: String,
    },
    /// CSR is done. Certificate can be downloaded ([`Account::obtain_certificate`](./struct.Account.html#method.obtain_certificate))
    Valid {
        /// URL to fetch the final Certificate
        certificate: String,
    },
    Invalid,
}

///Authentication status for a particular challange
///
/// Can be obtained by [`Account::check_auth`](./struct.Account.html#method.check_auth)
/// and is driven by triggering and completing challanges
#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Auth {
    /// challange must be triggered
    Pending {
        /// host to authenticate
        identifier: Identifier,
        /// challenges to complete in order to authenticate
        challenges: Vec<Challenge>,
    },
    /// ownership is proven
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
    RcgenError(#[from] rcgen::Error),
    #[error("error from cache: {0}")]
    Cache(Box<dyn CacheError>),
}

impl AcmeError {
    pub fn cache<E: CacheError>(err: E) -> Self {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::*;
    #[test]
    fn discover() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            let (mut stream, _) = listener.accept().await?;
            assert_stream(&mut stream, b"GET /directory HTTP").await?;

            let body = format!(
                r##"{{
                "keyChange": "host/key-change",
                "meta": {{
                  "caaIdentities": [
                    "letsencrypt.org"
                  ],
                  "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf",
                  "website": "https://letsencrypt.org/docs/staging-environment/"
                }},
                "newAccount": "host/new-acct",
                "newNonce": "host/new-nonce",
                "newOrder": "host/new-order",
                "q3Eo-_fidjY": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
                "renewalInfo": "https://acme-staging-v02.api.letsencrypt.org/draft-ietf-acme-ari-02/renewalInfo/",
                "revokeCert": "host/revoke-cert"
              }}"##
            );

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let t = spawn(server(listener));

            let d = Directory::discover(&format!("http://{}:{}/directory", host, port)).await?;
            assert_eq!(d.new_account, "host/new-acct");
            assert_eq!(d.new_nonce, "host/new-nonce");
            assert_eq!(d.new_order, "host/new-order");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
    pub async fn return_nounce(listener: &TcpListener) -> std::io::Result<bool> {
        let (mut stream, _) = listener.accept().await?;
        assert_stream(&mut stream, b"GET /acme/new-nonce HTTP").await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nreplay-nonce: abc\r\n\r\n")
            .await?;
        Ok(true)
    }
    pub fn new_dir(host: &str, port: u16) -> Directory {
        let new_nonce = format!("http://{}:{}/acme/new-nonce", host, port);
        let new_account = format!("http://{}:{}/acme/new-acct", host, port);
        let new_order = format!("http://{}:{}/acme/new-order", host, port);
        Directory {
            new_nonce,
            new_account,
            new_order,
        }
    }
    #[test]
    fn nonce() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            return_nounce(&listener).await
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let t = spawn(server(listener));

            let d = new_dir(&host, port);
            assert_eq!(d.nonce().await?, "abc");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
}
