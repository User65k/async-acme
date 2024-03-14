use async_acme::{
    acme::{AcmeError, ACME_TLS_ALPN_NAME, LETS_ENCRYPT_STAGING_DIRECTORY},
    rustls_helper::{duration_until_renewal_attempt, order},
};
use async_std::io::prelude::WriteExt;
use async_std::net::TcpListener;
use async_std::path::PathBuf;
use async_std::stream::StreamExt;
use async_std::task;
use async_std::task::sleep;
use futures_rustls::{
    rustls::{
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        ServerConfig,
    },
    TlsAcceptor,
};
use log;
use std::error::Error;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, RwLock, Weak},
    vec::Vec,
};

fn main() {
    pretty_env_logger::init();
    let cres = Arc::new(ResolveServerCert::new());
    let certres = Arc::downgrade(&cres);

    // Build TLS configuration.
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cres);

    cfg.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        ACME_TLS_ALPN_NAME.to_vec(),
    ];
    let tls_cfg = Arc::new(cfg);

    // Create a task to keep the cert valid
    let task = AcmeTaskRunner {
        certres,
        uri: LETS_ENCRYPT_STAGING_DIRECTORY.to_string(),
        contact: vec!["mailto:admin@example.com".to_string()],
        cache_dir: None,
        dns_names: vec!["example.com".to_string()],
    };
    task::spawn(async move {
        task.acme_watcher().await;
    });

    let acceptor = TlsAcceptor::from(tls_cfg);

    task::block_on(async move {
        serve(acceptor).await.unwrap();
    });
}
struct AcmeTaskRunner {
    /// resolver to update with a new cert
    certres: Weak<ResolveServerCert>,
    /// acme register to use
    uri: String,
    /// for acme request
    contact: Vec<String>,
    /// to store acme auth (and certs)
    cache_dir: Option<PathBuf>,
    /// dns to proof
    dns_names: Vec<String>,
}
pub struct ResolveServerCert {
    cert: RwLock<Option<Arc<CertifiedKey>>>,
    /// temp for acme challange
    acme_keys: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

/// ACME
impl AcmeTaskRunner {
    async fn acme_watcher(&self) {
        let mut err_cnt = 0usize;
        loop {
            let d = match self.certres.upgrade() {
                None => {
                    //ResolveServerCert is gone (and so is the TlsAcceptor)
                    break;
                }
                Some(resolver) => {
                    //check how long the current cert is still valid
                    let default = resolver.cert.read().unwrap();
                    duration_until_renewal_attempt(default.as_deref(), err_cnt)
                }
            };
            if d.as_secs() != 0 {
                log::info!("next renewal attempt in {}s", d.as_secs());
                sleep(d).await;
            }
            match order(
                |k, v| self.set_auth_key(k, v),
                &self.uri,
                &self.dns_names,
                self.cache_dir.as_ref(),
                &self.contact,
            )
            .await
            {
                Err(e) => {
                    eprintln!("ACME {}", e);
                    err_cnt += 1;
                }
                Ok(cert_key) => {
                    //let pk_pem = cert.serialize_private_key_pem();
                    //Self::save_certified_key(cache_dir, file_name, pk_pem, acme_cert_pem).await;

                    match self.certres.upgrade() {
                        None => {
                            //ResolveServerCert is gone (and so is the TlsAcceptor)
                            break;
                        }
                        Some(resolver) => {
                            resolver.cert.write().unwrap().replace(Arc::new(cert_key));
                        }
                    }
                    err_cnt = 0;
                }
            }
        }
    }
    fn set_auth_key(&self, key: String, cert: CertifiedKey) -> Result<(), AcmeError> {
        match self.certres.upgrade() {
            Some(resolver) => {
                resolver
                    .acme_keys
                    .write()
                    .unwrap()
                    .insert(key, Arc::new(cert));
                Ok(())
            }
            None => Err(std::io::Error::new(io::ErrorKind::BrokenPipe, "TLS shut down").into()),
        }
    }
}

impl std::fmt::Debug for ResolveServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveServerCert").finish()
    }
}
impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if client_hello
            .alpn()
            .and_then(|mut iter| iter.find(|alpn| *alpn == ACME_TLS_ALPN_NAME))
            .is_some()
        {
            //return a not yet signed cert
            return match client_hello.server_name() {
                None => None,
                Some(domain) => self.acme_keys.read().unwrap().get(domain).cloned(),
            };
        };

        //do your thing to resolve your cert
        self.cert.read().unwrap().as_ref().cloned()
    }
}
impl ResolveServerCert {
    pub fn new() -> ResolveServerCert {
        ResolveServerCert {
            cert: RwLock::new(None),
            acme_keys: RwLock::new(HashMap::new()),
        }
    }
}

async fn serve(acceptor: TlsAcceptor) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    while let Some(tcp) = listener.incoming().next().await {
        let acceptor = acceptor.clone();
        task::spawn(async move {
            if let Ok(mut tls) = acceptor.accept(tcp.unwrap()).await {
                tls.write_all(HELLO).await.unwrap();
            }
        });
    }
    Ok(())
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
