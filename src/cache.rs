/*! Ways to cache account data and certificates.

A default implementation for `AsRef<Path>` (`Sting`, `OsString`, `PathBuf`, ...)
allows the use of a local directory as cache.
*/

use std::{io::{Error as IoError, ErrorKind}, path::Path};

use async_trait::async_trait;

#[cfg(feature = "use_async_std")]
use async_std::fs::{create_dir_all as cdall, read, write};
#[cfg(feature = "use_tokio")]
use tokio::fs::{create_dir_all, read, write};

use crate::crypto::sha256_hasher;

/// Trait to define a custom location/mechanism to cache account data and certificates.
#[async_trait]
pub trait AcmeCache {
    /// The error type returned from the functions on this trait.
    type Error: CacheError;

    /// Returns the previously written data for `contacts`, if any. This
    /// function should return `None` instead of erroring if data was not
    /// previously written for `contacts`.
    async fn read_account(&self, contacts: &[&str]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Writes `data` for `contacts`. The data being written is unique for the
    /// combined list of `contacts`.
    ///
    /// # Errors
    ///
    /// Returns an error when `data` was unable to be written successfully.
    async fn write_account(&self, contacts: &[&str], data: &[u8]) -> Result<(), Self::Error>;

    /// Writes a certificate retrieved from `Acme`. The parameters are:
    ///
    /// ## Parameters
    ///
    /// * `domains`: the list of domains included in the certificate.
    /// * `directory_url`: the Url of the `Acme` directory that this certificate
    ///   was issued form.
    /// * `key_pem`: the private key, encoded in PEM format.
    /// * `certificate_pem`: the certificate chain, encoded in PEM format.
    ///
    /// ## Errors
    ///
    /// Returns an error when the certificate was unable to be written
    /// sucessfully.
    async fn write_certificate(
        &self,
        domains: &[String],
        directory_url: &str,
        key_pem: &str,
        certificate_pem: &str,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
impl<P> AcmeCache for P
where
    P: AsRef<Path> + Send + Sync,
{
    type Error = IoError;

    async fn read_account(&self, contacts: &[&str]) -> Result<Option<Vec<u8>>, Self::Error> {
        let file = cached_key_file_name(contacts);
        let mut path = self.as_ref().to_path_buf();
        path.push(file);
        match read(path).await {
            Ok(content) => Ok(Some(content)),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            },
        }
    }

    async fn write_account(&self, contacts: &[&str], contents: &[u8]) -> Result<(), Self::Error> {
        let mut path = self.as_ref().to_path_buf();
        create_dir_all(&path).await?;
        path.push(cached_key_file_name(contacts));
        Ok(write(path, contents).await?)
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

/// An error that can be returned from an [`AcmeCache`].
pub trait CacheError: std::error::Error + Send + Sync + 'static {}

impl<T> CacheError for T where T: std::error::Error + Send + Sync + 'static {}

#[cfg(feature = "use_async_std")]
async fn create_dir_all(a: impl AsRef<Path>) -> Result<(), IoError> {
    let p = a.as_ref();
    let p = <&async_std::path::Path>::from(p);
    cdall(p).await
}

#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
async fn create_dir_all(_a: impl AsRef<Path>) -> Result<(), IoError> {
    Err(IoError::new(ErrorKind::NotFound, "no async backend selected"))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
async fn read(_a: impl AsRef<Path>) -> Result<Vec<u8>, IoError> {
    Err(IoError::new(ErrorKind::NotFound, "no async backend selected"))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
async fn write(_a: impl AsRef<Path>, _c: impl AsRef<[u8]>) -> Result<(), IoError> {
    Err(IoError::new(ErrorKind::NotFound, "no async backend selected"))
}

fn cached_key_file_name(contact: &[&str]) -> String {
    let mut ctx = sha256_hasher();
    for el in contact {
        ctx.update(el.as_ref());
        ctx.update(&[0])
    }
    let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
    format!("cached_account_{}", hash)
}
