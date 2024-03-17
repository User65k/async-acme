use rcgen::{
    Certificate, CertificateParams, CustomExtension, DistinguishedName, Error as RcgenError,
    PKCS_ECDSA_P256_SHA256,
};
use ring::{
    digest::{digest, Context, SHA256 as DoSHA256},
    error::Unspecified,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};

use rustls::{
    sign::{CertifiedKey, SigningKey},
    crypto::ring::sign::any_ecdsa_type,
    pki_types::PrivateKeyDer,
};

use std::sync::Arc;

#[derive(Debug)]
pub struct EcdsaP256SHA256KeyPair(EcdsaKeyPair);

impl EcdsaP256SHA256KeyPair {
    pub fn load(pkcs8: &[u8]) -> Result<EcdsaP256SHA256KeyPair, ()> {
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        EcdsaKeyPair::from_pkcs8(alg, pkcs8, &SystemRandom::new())
            .map_err(|_| ())
            .map(EcdsaP256SHA256KeyPair)
    }
    pub fn generate() -> Result<impl AsRef<[u8]>, ()> {
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        let rng = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(alg, &rng).map_err(|_| ())
    }
    pub fn sign(&self, message: &[u8]) -> Result<impl AsRef<[u8]>, Unspecified> {
        self.0.sign(&SystemRandom::new(), message)
    }
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }
}

pub fn sha256_hasher() -> Context {
    Context::new(&DoSHA256)
}
pub fn sha256(data: &[u8]) -> impl AsRef<[u8]> {
    digest(&DoSHA256, data)
}
pub fn gen_acme_cert(domains: Vec<String>, acme_hash: &[u8]) -> Result<CertifiedKey, RcgenError> {
    let mut params = CertificateParams::new(domains);
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(acme_hash)];
    let cert = Certificate::from_params(params)?;
    let key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into())).unwrap();
    Ok(CertifiedKey::new(
        vec![cert.serialize_der()?.into()],
        key,
    ))
}

pub struct CertBuilder {
    cert: Certificate,
    pk: Arc<dyn SigningKey>,
}
impl CertBuilder {
    pub fn gen_new(domains: Vec<String>) -> Result<CertBuilder, RcgenError> {
        let mut params = CertificateParams::new(domains);
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = Certificate::from_params(params)?;
        let pk = any_ecdsa_type(&PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into())).unwrap();

        Ok(CertBuilder { cert, pk })
    }
    pub fn get_csr(&self) -> Result<Vec<u8>, RcgenError> {
        self.cert.serialize_request_der()
    }
    pub fn private_key_as_pem_pkcs8(&self) -> String {
        self.cert.serialize_private_key_pem()
    }
    pub fn sign(self, mut pem_cert: &[u8]) -> Result<CertifiedKey, ()> {
        let cert_chain = rustls_pemfile::certs(&mut pem_cert)
            .filter_map(|e|e.ok())
            .collect();
        let cert_key = CertifiedKey::new(cert_chain, self.pk);
        Ok(cert_key)
    }
}
