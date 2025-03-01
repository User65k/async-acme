#[cfg(all(feature = "rustls_ring", feature = "use_openssl"))]
compile_error!("Only one of the 'rustls_ring' or 'use_openssl' features can be activated");

#[cfg(any(feature = "rustls_ring", feature = "rustls_aws_lc_rs"))]
mod rustls;
#[cfg(any(feature = "rustls_ring", feature = "rustls_aws_lc_rs"))]
pub use self::rustls::{gen_acme_cert, sha256, sha256_hasher, CertBuilder, EcdsaP256SHA256KeyPair};
#[cfg(feature = "use_openssl")]
mod openssl;
#[cfg(feature = "use_openssl")]
pub use self::openssl::{
    gen_acme_cert, sha256, sha256_hasher, CertBuilder, EcdsaP256SHA256KeyPair,
};

#[cfg(not(any(
    feature = "rustls_ring",
    feature = "use_openssl",
    feature = "rustls_aws_lc_rs"
)))]
mod dummy;
#[cfg(not(any(
    feature = "rustls_ring",
    feature = "use_openssl",
    feature = "rustls_aws_lc_rs"
)))]
pub use self::dummy::{gen_acme_cert, sha256, sha256_hasher, CertBuilder, EcdsaP256SHA256KeyPair};
