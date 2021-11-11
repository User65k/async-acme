#[cfg(feature = "use_async_std")]
pub use async_std::fs::{create_dir_all as cdall, read, write};
#[cfg(feature = "use_tokio")]
pub use tokio::fs::{create_dir_all, read, write};

use std::{
    io::{Error, ErrorKind},
    path::Path,
};

#[cfg(feature = "use_async_std")]
pub async fn create_dir_all(a: impl AsRef<Path>) -> Result<(), Error> {
    let p = a.as_ref();
    let p = <(&async_std::path::Path)>::from(p);
    cdall(p).await
}

pub(crate) async fn read_if_exist(
    dir: impl AsRef<Path>,
    file: impl AsRef<Path>,
) -> Result<Option<Vec<u8>>, Error> {
    let path = dir.as_ref().join(file);
    match read(path).await {
        Ok(content) => Ok(Some(content)),
        Err(err) => match err.kind() {
            ErrorKind::NotFound => Ok(None),
            _ => Err(err),
        },
    }
}

pub(crate) async fn write_file(
    dir: impl AsRef<Path>,
    file: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<(), Error> {
    let path = dir.as_ref().join(file);
    Ok(write(path, contents).await?)
}

#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
pub async fn create_dir_all(_a: impl AsRef<Path>) -> Result<(), Error> {
    Err(Error::new(ErrorKind::NotFound, "no async backend selected"))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
pub async fn read(_a: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    Err(Error::new(ErrorKind::NotFound, "no async backend selected"))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
pub async fn write(_a: impl AsRef<Path>, _c: impl AsRef<[u8]>) -> Result<(), Error> {
    Err(Error::new(ErrorKind::NotFound, "no async backend selected"))
}
