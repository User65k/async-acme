use openssl::hash::MessageDigest;
pub use openssl::sha::sha256;
use openssl::stack::Stack;
use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::{ECDSA_WITH_SHA256, SUBJECT_ALTERNATIVE_NAME},
    pkcs12::Pkcs12Builder,
    pkey::PKey,
    sha::Sha256,
    x509::{
        extension::SubjectAlternativeName, X509Builder, X509Extension, X509Name, X509Req, X509,
    },
};

use tokio_native_tls::native_tls::Identity;

#[derive(Debug)]
pub struct EcdsaP256SHA256KeyPair(EcKey);

impl EcdsaP256SHA256KeyPair {
    pub fn load(pkcs8: &[u8]) -> Result<EcdsaP256SHA256KeyPair, ()> {
        match EcKey::private_key_from_pkcs8(pkcs8).and_then(|pkey| pkey.try_into()) {
            Ok(key) => Ok(EcdsaP256SHA256KeyPair(key)),
            Err(_) => return Err(()),
        }
    }
    pub fn generate() -> Result<impl AsRef<[u8]>, ()> {
        let ec = EcKey::generate(EcGroup::from_curve_name(ECDSA_WITH_SHA256));
        match ec.private_key_to_pem_pkcs8() {
            Ok(vec) => Ok(vec),
            Err(_) => Err(()),
        }
    }
    pub fn sign(&self, message: &[u8]) -> Result<impl AsRef<[u8]>, ErrorStack> {
        EcdsaSig::sign(message, &self.0)?.to_der()
    }
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key_to_der().unwrap()
    }
}

pub fn sha256_hasher() -> Sha256 {
    Sha256::new()
}

pub fn gen_acme_cert(domains: Vec<String>, acme_hash: &[u8]) -> Result<Identity, ErrorStack> {
    let builder = X509Builder::new()?;
    let name = {
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", &domains[0])?;
        name.build()
    };
    builder.set_subject_name(&name)?;

    // Add all domains as SANs
    let san_extension = {
        let mut san = SubjectAlternativeName::new();
        for domain in domains.iter() {
            san.dns(domain);
        }
        san.build(&builder.x509v3_context(None))?
    };
    let mut stack = Stack::new()?;
    stack.push(san_extension)?;
    builder.add_extensions(&stack)?;

    builder.append_extension(X509Extension::new(None, None, "1.3.6.1.5.5.7.1.31", "")?)?; //OID_PE_ACME

    let pkey = PKey::from_ec_key(EcKey::generate(EcGroup::from_curve_name(ECDSA_WITH_SHA256)));

    builder.set_pubkey(&pkey)?;
    builder.sign(&pkey, MessageDigest::sha256())?;

    let cert = builder.build();
    Pkcs12Builder::build("", "", &pkey, &cert)?;
    Identity::from_pkcs12(der, "")?;
}

pub struct CertBuilder {
    req: X509Req,
    pkey: PKey,
}
impl CertBuilder {
    pub fn gen_new(domains: Vec<String>) -> Result<CertBuilder, ErrorStack> {
        let mut builder = X509Req::builder()?;
        let name = {
            let mut name = X509Name::builder()?;
            name.append_entry_by_text("CN", &domains[0])?;
            name.build()
        };
        builder.set_subject_name(&name)?;

        // Add all domains as SANs
        let san_extension = {
            let mut san = SubjectAlternativeName::new();
            for domain in domains.iter() {
                san.dns(domain);
            }
            san.build(&builder.x509v3_context(None))?
        };
        let mut stack = Stack::new()?;
        stack.push(san_extension)?;
        builder.add_extensions(&stack)?;

        let pkey = PKey::from_ec_key(EcKey::generate(EcGroup::from_curve_name(ECDSA_WITH_SHA256)));

        builder.set_pubkey(&pkey)?;
        builder.sign(&pkey, MessageDigest::sha256())?;

        let req = builder.build();
        Ok(CertBuilder { req, pkey })
    }
    pub fn get_csr(&self) -> Result<Vec<u8>, ErrorStack> {
        self.req.to_der()
    }
    pub fn private_key_as_pem_pkcs8(&self) -> Result<Vec<u8>, ErrorStack> {
        self.pkey.private_key_to_pem_pkcs8()
    }
    pub fn sign(self, mut pem_cert: &[u8]) -> Result<Identity, ()> {
        let cert = X509::stack_from_pem(&pem_cert)?;
        Pkcs12Builder::build("", "", &self.pkey, &cert)?;
        Identity::from_pkcs12(der, "")?;
    }
}
