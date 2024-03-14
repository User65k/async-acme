use async_acme::{
    acme::{AcmeError, ACME_TLS_ALPN_NAME, LETS_ENCRYPT_STAGING_DIRECTORY},
    rustls_helper::{duration_until_renewal_attempt, order},
};
use tokio::time::sleep;

use hyper::{
    service::service_fn,
    body::Incoming as Body, Method, Request, Response, StatusCode,
};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{Arc, RwLock, Weak},
    vec::Vec,
};
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        ServerConfig,
    },
    TlsAcceptor,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};

#[tokio::main]
async fn main() {
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
    tokio::spawn(async move {
        task.acme_watcher().await;
    });

    // Create a TCP listener via tokio.
    let addr = "0.0.0.0:443";
    let tcp = TcpListener::bind(&addr).await.expect("bind failed");
    let tls_acceptor = Arc::new(TlsAcceptor::from(tls_cfg));
    // Prepare a long-running future stream to accept and serve clients.
    while let Ok((stream, _)) = tcp.accept().await {
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let stream = tls_acceptor.accept(stream).await.expect("tls handshake");
            auto::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(stream),
                        service_fn(echo),
                    )
                    .await.expect("serve_connection");
        });
    }

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}.", addr);
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

#[derive(Default)]
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
                    match self.certres.upgrade() {
                        None => {
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
        Self::default()
    }
}

async fn echo(req: Request<Body>) -> Result<Response<String>, hyper::Error> {
    let mut response = Response::new(String::new());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = "Try POST /echo\n".to_string();
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = "This was once returning the request body\n".to_string();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}
