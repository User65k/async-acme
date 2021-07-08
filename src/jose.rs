use base64::URL_SAFE_NO_PAD;
use serde::Serialize;
use crate::crypto::{sha256, EcdsaP256SHA256KeyPair};
use generic_async_http_client::{Request, Response};
use crate::acme::AcmeError;

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
    let payload = base64::encode_config(payload, URL_SAFE_NO_PAD);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = match key.sign(combined.as_bytes()){
        Ok(s) => s,
        Err(_) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "could not sign jose request").into());
        }
    };
    let signature = base64::encode_config(signature.as_ref(), URL_SAFE_NO_PAD);
    let body = Body {
        protected,
        payload,
        signature,
    };
    let req = Request::post(url)
        .json(&body)?
        .set_header("Content-Type","application/jose+json")?;
    log::debug!("{:?}", req);
    let mut response = req.exec().await?;
    if response.status_code() > 299 {
        if let Ok(s) = response.text().await {
            log::error!("{}: HTTP {} - {}", url, response.status_code(), s);
        }else{
            log::error!("{}: HTTP {}", url, response.status_code());
        }
        return Err(AcmeError::HttpStatus(response.status_code()));
    }
    Ok(response)
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
        Ok(base64::encode_config(protected, URL_SAFE_NO_PAD))
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
            x: base64::encode_config(x, URL_SAFE_NO_PAD),
            y: base64::encode_config(y, URL_SAFE_NO_PAD),
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
        Ok(base64::encode_config(hash, URL_SAFE_NO_PAD))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}
