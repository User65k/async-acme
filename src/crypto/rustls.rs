#[cfg(feature = "rustls_aws_lc_rs")]
use aws_lc_rs::{
    digest::{digest, Context, SHA256 as DoSHA256},
    error::Unspecified,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, Error as RcgenError,
    PKCS_ECDSA_P256_SHA256,
};
#[cfg(feature = "rustls_ring")]
use ring::{
    digest::{digest, Context, SHA256 as DoSHA256},
    error::Unspecified,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};

#[cfg(feature = "rustls_aws_lc_rs")]
use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
#[cfg(feature = "rustls_ring")]
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::{pki_types::PrivateKeyDer, sign::CertifiedKey};

#[derive(Debug)]
pub struct EcdsaP256SHA256KeyPair(EcdsaKeyPair);

impl EcdsaP256SHA256KeyPair {
    pub fn load(pkcs8: &[u8]) -> Result<EcdsaP256SHA256KeyPair, ()> {
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        EcdsaKeyPair::from_pkcs8(
            alg,
            pkcs8,
            #[cfg(feature = "rustls_ring")]
            &SystemRandom::new(),
        )
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
/// generate a self signed certificate to use during the TLS challange
pub fn gen_acme_cert(domains: Vec<String>, acme_hash: &[u8]) -> Result<CertifiedKey, RcgenError> {
    let mut params = CertificateParams::new(domains)?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(acme_hash)];
    let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;
    let key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_pair.serialized_der().into())).unwrap();
    Ok(CertifiedKey::new(vec![cert.into()], key))
}

pub struct CertBuilder {
    params: CertificateParams,
    kp: rcgen::KeyPair,
}
impl CertBuilder {
    pub fn gen_new(domains: Vec<String>) -> Result<CertBuilder, RcgenError> {
        let mut params = CertificateParams::new(domains)?;
        params.distinguished_name = DistinguishedName::new();
        let kp = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        Ok(CertBuilder { params, kp })
    }
    pub fn get_csr(&self) -> Result<Vec<u8>, RcgenError> {
        Ok(self.params.serialize_request(&self.kp)?.der().to_vec())
    }
    pub fn private_key_as_pem_pkcs8(&self) -> String {
        self.kp.serialize_pem()
    }
    pub fn sign(self, mut pem_cert: &[u8]) -> Result<CertifiedKey, ()> {
        let cert_chain = rustls_pemfile::certs(&mut pem_cert)
            .filter_map(|e| e.ok())
            .collect();
        let pk = any_ecdsa_type(&PrivateKeyDer::Pkcs8(self.kp.serialized_der().into())).unwrap();
        let cert_key = CertifiedKey::new(cert_chain, pk);
        Ok(cert_key)
    }
}
