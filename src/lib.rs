/*! A generic async ACME create.

Binaries can choose what async runtime and TLS lib is used.

You need to specify via features what crates are used to the actual work.
Without anything specified you will end up with *no async backend selected* or *no crypto backend selected*.

To get a certificate from an ACME provider you
create an [`acme::Account`] and then drive the order on it.
Refer to [`acme::Account`] for the steps of a Order.
```
use async_acme::{
    acme::{LETS_ENCRYPT_STAGING_DIRECTORY, Directory, Account},

};
async fn create_account() -> Account {
    let cache = "./cachedir/".to_string();
    let directory = Directory::discover(LETS_ENCRYPT_STAGING_DIRECTORY).await.unwrap();
    Account::load_or_create(
        directory,
        Some(&cache),
        &vec!["mailto:admin@example.com".to_string()]
    ).await.unwrap()
}
```

If you are using rustls, you probably want to just use [`rustls_helper::order`].

[`rustls_helper::order`]: ./rustls_helper/fn.order.html
[`acme::Account`]: ./acme/struct.Account.html
*/
#![cfg_attr(docsrs, feature(doc_cfg))]

use base64::{
    alphabet::URL_SAFE,
    engine::{general_purpose::NO_PAD, GeneralPurpose},
};

const B64_URL_SAFE_NO_PAD: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, NO_PAD);

pub mod acme;
pub mod cache;
mod crypto;
mod jose;

#[cfg(feature = "use_rustls")]
#[cfg_attr(docsrs, doc(cfg(feature = "use_rustls")))]
pub mod rustls_helper;

#[cfg(test)]
pub(crate) mod test {
    #[cfg(feature = "use_async_std")]
    pub(crate) use async_std::{
        io::prelude::{ReadExt, WriteExt},
        net::{TcpListener, TcpStream},
        task::spawn,
    };
    #[cfg(feature = "use_async_std")]
    pub(crate) fn block_on(
        fut: impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
    ) {
        async_std::task::block_on(fut).expect("block_on failed")
    }
    //use futures::{AsyncWriteExt};
    #[cfg(feature = "use_tokio")]
    pub(crate) use tokio::{
        io::{AsyncReadExt as ReadExt, AsyncWriteExt as WriteExt},
        net::{TcpListener, TcpStream},
        runtime::Builder,
    };
    #[cfg(feature = "use_tokio")]
    pub(crate) fn block_on(
        fut: impl std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
    ) {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt")
            .block_on(fut)
            .expect("block_on failed")
    }
    #[cfg(feature = "use_tokio")]
    pub(crate) fn spawn<T>(fut: T) -> impl std::future::Future<Output = T::Output>
    where
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static,
    {
        let jh = tokio::task::spawn(fut);
        async { jh.await.expect("spawn failed") }
    }
    pub(crate) async fn close(mut stream: TcpStream) -> std::io::Result<()> {
        stream.flush().await?;
        #[cfg(feature = "use_tokio")]
        stream.shutdown().await?;
        #[cfg(feature = "use_async_std")]
        stream.shutdown(async_std::net::Shutdown::Both)?;
        Ok(())
    }

    pub(crate) async fn assert_stream(
        stream: &mut TcpStream,
        should_be: &[u8],
    ) -> std::io::Result<()> {
        let l = should_be.len();
        let mut req: Vec<u8> = vec![0; l];
        let _r = stream.read(req.as_mut_slice()).await?;
        assert_eq!(req, should_be);
        Ok(())
    }
    pub(crate) async fn listen_somewhere() -> Result<(TcpListener, u16, String), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok((listener, addr.port(), addr.ip().to_string()))
    }
}
