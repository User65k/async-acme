use async_acme::{
    acme::{AcmeError, ACME_TLS_ALPN_NAME, LETS_ENCRYPT_STAGING_DIRECTORY},
    rustls_helper::{duration_until_renewal_attempt, order},
};
use tokio::time::sleep;

use async_stream::stream;
use core::task::{Context, Poll};
use futures_util::stream::Stream;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, RwLock, Weak},
    vec::Vec,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        ServerConfig,
    },
    server::TlsStream,
    TlsAcceptor,
};

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let cres = Arc::new(ResolveServerCert::new());
    let certres = Arc::downgrade(&cres);

    // Build TLS configuration.
    let mut cfg = ServerConfig::builder()
        .with_safe_defaults()
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
    let tls_acceptor = TlsAcceptor::from(tls_cfg);
    // Prepare a long-running future stream to accept and serve clients.
    let incoming_tls_stream = stream! {
        loop {
            let (socket, _) = tcp.accept().await?;
            let stream = tls_acceptor.accept(socket);
            yield stream.await;
        }
    };
    let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(echo)) });
    let server = Server::builder(HyperAcceptor {
        acceptor: Box::pin(incoming_tls_stream),
    })
    .serve(service);

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}.", addr);
    server.await.expect("server failed");
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

async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}

struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + 'a>>,
}

impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}
