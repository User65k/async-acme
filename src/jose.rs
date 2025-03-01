use crate::acme::AcmeError;
use crate::crypto::{sha256, EcdsaP256SHA256KeyPair};
use crate::B64_URL_SAFE_NO_PAD;
use base64::Engine;
use generic_async_http_client::{Request, Response};
use serde::Serialize;

/// Send a signed JOSE request to an endpoint
pub async fn jose_req(
    key: &EcdsaP256SHA256KeyPair,
    kid: Option<&str>,
    nonce: &str,
    url: &str,
    payload: &str,
) -> Result<Response, AcmeError> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::base64(jwk, kid, nonce, url)?;
    let payload = B64_URL_SAFE_NO_PAD.encode(payload);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = match key.sign(combined.as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "could not sign jose request",
            )
            .into());
        }
    };
    let signature = B64_URL_SAFE_NO_PAD.encode(signature.as_ref());
    let body = Body {
        protected,
        payload,
        signature,
    };
    loop {
        let req = Request::post(url)
            .json(&body)?
            .set_header("Content-Type", "application/jose+json")?;
        log::debug!("{:?}", req);
        let mut response = req.exec().await?;
        break match response.status_code() {
            100..300 => Ok(response),
            redir @ 300..400 => Err(AcmeError::HttpStatus(redir)), //we are not discovering - there should be no redirect
            code => {
                if let Ok(s) = response.json::<ProblemDetails>().await {
                    if s.t == "urn:ietf:params:acme:error:rateLimited" /*&& matches!(code, 500..600)*/ {
                        //HTTP 5xx error -> try again after some time
                        if let Some(retry) = response
                            .header("retry-after")
                            .and_then(|h| std::str::from_utf8(h.as_ref()).ok())
                            .and_then(|s| s.parse().ok())
                        {
                            log::info!("Received Retry-After header, waiting {retry} seconds...");
                            crate::sleep(std::time::Duration::from_secs(retry)).await;
                            continue;
                        }
                    }
                    log::error!("{}: HTTP {} - {:?} {:?}", url, code, s.title, s.detail);
                } else {
                    log::error!("{}: HTTP {}", url, code);
                }
                Err(AcmeError::HttpStatus(code))
            },
        }
    }
}


#[derive(Debug, serde::Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    t: String,
    title: Option<String>,
    detail: Option<String>,
}

pub(crate) fn key_authorization_sha256(
    key: &EcdsaP256SHA256KeyPair,
    token: &str,
) -> Result<impl AsRef<[u8]>, AcmeError> {
    let jwk = Jwk::new(key);
    let key_authorization = format!("{}.{}", token, jwk.thumb_sha256_base64()?);
    Ok(sha256(key_authorization.as_bytes()))
}

#[derive(Serialize)]
struct Body {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

impl<'a> Protected<'a> {
    fn base64(
        jwk: Option<Jwk>,
        kid: Option<&'a str>,
        nonce: &'a str,
        url: &'a str,
    ) -> Result<String, AcmeError> {
        let protected = Self {
            alg: "ES256",
            jwk,
            kid,
            nonce,
            url,
        };
        let protected = serde_json::to_vec(&protected)?;
        Ok(B64_URL_SAFE_NO_PAD.encode(protected))
    }
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaP256SHA256KeyPair) -> Self {
        let (x, y) = key.public_key()[1..].split_at(32);
        Self {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: B64_URL_SAFE_NO_PAD.encode(x),
            y: B64_URL_SAFE_NO_PAD.encode(y),
        }
    }
    pub(crate) fn thumb_sha256_base64(&self) -> Result<String, AcmeError> {
        let jwk_thumb = JwkThumb {
            crv: self.crv,
            kty: self.kty,
            x: &self.x,
            y: &self.y,
        };
        let json = serde_json::to_vec(&jwk_thumb)?;
        let hash = sha256(&json);
        Ok(B64_URL_SAFE_NO_PAD.encode(hash))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}
