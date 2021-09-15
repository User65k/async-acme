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

pub mod acme;
pub mod cache;
mod crypto;
mod jose;

#[cfg(feature = "use_rustls")]
pub mod rustls_helper;
