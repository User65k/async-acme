use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::parse_x509_certificate;

#[cfg(all(feature = "use_rustls", feature = "use_openssl"))]
compile_error!("Only one of the 'use_rustls' or 'use_openssl' features can be activated");

#[cfg(feature = "use_rustls")]
mod ring;
#[cfg(feature = "use_rustls")]
pub use self::ring::{gen_acme_cert, sha256, sha256_hasher, CertBuilder, EcdsaP256SHA256KeyPair};
#[cfg(feature = "use_openssl")]
mod openssl;
#[cfg(feature = "use_openssl")]
pub use self::openssl::{
    gen_acme_cert, sha256, sha256_hasher, CertBuilder, EcdsaP256SHA256KeyPair,
};

#[cfg_attr(not(feature = "use_rustls"), allow(dead_code))]
pub fn get_cert_duration_left(x509_cert: &[u8]) -> Result<Duration, ()> {
    let valid_until = match parse_x509_certificate(x509_cert) {
        Ok((_, cert)) => cert.validity().not_after.timestamp() as u64,
        Err(_err) => {
            return Err(());
        }
    };

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    Ok(Duration::from_secs(valid_until).saturating_sub(since_the_epoch))
}

#[cfg(not(any(feature = "use_rustls", feature = "use_openssl")))]
mod dummy;
#[cfg(not(any(feature = "use_rustls", feature = "use_openssl")))]
pub use self::dummy::{gen_acme_cert, sha256, sha256_hasher, CertBuilder, EcdsaP256SHA256KeyPair};
