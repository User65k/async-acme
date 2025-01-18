use serde_json::json;

use crate::{
    acme::{get_header, AcmeError, Auth, Challenge, ChallengeType, Directory, Identifier, Order},
    cache::AcmeCache,
    crypto::EcdsaP256SHA256KeyPair,
    jose::{jose_req, key_authorization_sha256},
    B64_URL_SAFE_NO_PAD,
};
use base64::Engine;
use generic_async_http_client::Response;

/// An Acout at an ACME provider. Used to query certificates and challanges
///
/// 1. `load_or_create` your Account
/// 2. place a `new_order` for your domains
/// 3. `check_auth` for a single domain, if valid move to 6.
/// 4. use `tls_alpn_01` to get a certificate for it
/// 5. `trigger_challenge` on that domain
/// 6. repeat 3. - 5. for all other domains
/// 7. `send_csr` for your cert ...
/// 8. ... and finally `obtain_certificate`
#[derive(Debug)]
pub struct Account {
    key_pair: EcdsaP256SHA256KeyPair,
    directory: Directory,
    kid: String,
}

impl Account {
    /// Create or load a cached Account for ACME provider at `directory`.
    /// Provide your email in `contact` in the form *mailto:admin@example.com* to receive warnings regarding your certificate.
    /// Set a `cache` to remember/load your account.
    pub async fn load_or_create<'a, C, S, I>(
        directory: Directory,
        cache: Option<&C>,
        contact: I,
    ) -> Result<Self, AcmeError>
    where
        C: AcmeCache,
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();
        let pkcs8 = match &cache {
            Some(cache) => cache
                .read_account(&contact)
                .await
                .map_err(AcmeError::cache)?,
            None => None,
        };
        let key_pair = match pkcs8 {
            Some(pkcs8) => {
                log::info!("found cached account key");
                EcdsaP256SHA256KeyPair::load(&pkcs8)
            }
            None => {
                log::info!("creating a new account key");
                match EcdsaP256SHA256KeyPair::generate() {
                    Ok(pkcs8) => {
                        let data = pkcs8.as_ref();
                        if let Some(cache) = &cache {
                            cache
                                .write_account(&contact, data)
                                .await
                                .map_err(AcmeError::cache)?;
                        }
                        EcdsaP256SHA256KeyPair::load(data)
                    }
                    Err(_) => Err(()),
                }
            }
        }
        .map_err(|_| {
            AcmeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "could not create key pair",
            ))
        })?;
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": contact,
        })
        .to_string();
        let response = jose_req(
            &key_pair,
            None,
            &directory.nonce().await?,
            &directory.new_account,
            &payload,
        )
        .await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
        })
    }
    /// send a JOSE request using the own Key to sign it
    async fn request(&self, url: impl AsRef<str>, payload: &str) -> Result<Response, AcmeError> {
        jose_req(
            &self.key_pair,
            Some(&self.kid),
            &self.directory.nonce().await?,
            url.as_ref(),
            payload,
        )
        .await
    }
    /// send a new order for the DNS identifiers in domains
    pub async fn new_order(&self, domains: Vec<String>) -> Result<Order, AcmeError> {
        let domains: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let mut response = self.request(&self.directory.new_order, &payload).await?;
        Ok(response.json().await?)
    }
    /// check the authentication status for a particular challange
    pub async fn check_auth(&self, url: impl AsRef<str>) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let mut response = self.request(url, &payload).await?;
        Ok(response.json().await?)
    }
    /// trigger a particular challange
    pub async fn trigger_challenge(&self, url: impl AsRef<str>) -> Result<(), AcmeError> {
        self.request(&url, "{}").await?;
        Ok(())
    }
    /// request a certificate to be signed
    pub async fn send_csr(&self, url: impl AsRef<str>, csr: Vec<u8>) -> Result<Order, AcmeError> {
        let payload = format!("{{\"csr\":\"{}\"}}", B64_URL_SAFE_NO_PAD.encode(csr));
        let mut response = self.request(&url, &payload).await?;
        Ok(response.json().await?)
    }
    /// obtain a signed certificate for a privious CSR
    pub async fn obtain_certificate(&self, url: impl AsRef<str>) -> Result<String, AcmeError> {
        Ok(self.request(&url, "").await?.text().await?)
    }
    /// return a hash for first alpn challange.
    /// the hash needs to be presented inside the TLS certificate when the ACME TLS ALPN is present
    pub fn tls_alpn_01<'a>(
        &self,
        challenges: &'a [Challenge],
    ) -> Result<(&'a Challenge, impl AsRef<[u8]>), AcmeError> {
        let challenge = challenges
            .iter()
            .find(|c| c.typ == ChallengeType::TlsAlpn01);
        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let key_auth = key_authorization_sha256(&self.key_pair, &*challenge.token)?;

        Ok((challenge, key_auth))
    }
}

#[cfg(test)]
#[cfg(any(feature = "use_async_std", feature = "use_tokio"))]
mod test {
    use std::collections::HashMap;

    use super::*;
    use crate::acme::test::{new_dir, return_nounce};
    use crate::test::*;

    fn parse_req(req: Vec<u8>) -> (String, Option<serde_json::Map<String, serde_json::Value>>, serde_json::Map<String, serde_json::Value>) {
        let req = String::from_utf8(req).expect("request not utf8");

        let parts = req.split_once("\r\n\r\n").expect("no body");

        let body: HashMap<String, String> =
            serde_json::from_str(parts.1).expect("body not json");

        let payload = body.get("payload").expect("no payload");
        let payload = if payload.is_empty() {
            None
        }else{
            let payload: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(
                &B64_URL_SAFE_NO_PAD
                    .decode(payload)
                    .expect("b64"),
            )
            .expect("payload not json");
            Some(payload)
        };

        let protected: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(
            &B64_URL_SAFE_NO_PAD
                .decode(body.get("protected").expect("no protected"))
                .expect("b64"),
        )
        .expect("protected not json");
        (parts.0.to_owned(), payload, protected)
    }

    #[test]
    fn new() {
        async fn server(listener: TcpListener, host: String, port: u16) -> std::io::Result<bool> {
            return_nounce(&listener).await?;
            let (mut stream, _) = listener.accept().await?;
            let mut req: Vec<u8> = vec![0; 1024];
            let r = stream.read(req.as_mut_slice()).await?;
            let (header, payload, protected) = parse_req(req[0..r].to_vec());
            let payload = payload.expect("no payload");
            assert!(header.starts_with("POST /acme/new-acct HTTP"));

            assert_eq!(payload.get("termsOfServiceAgreed"), Some(&true.into()));
            assert_eq!(
                payload
                    .get("contact")
                    .expect("no contact")
                    .as_array()
                    .expect("no contact array")
                    .first(),
                Some(&"mailto:admin@example.com".into())
            );

            assert_eq!(protected.get("alg"), Some(&"ES256".into()));
            assert_eq!(protected.get("nonce"), Some(&"abc".into()));
            assert_eq!(
                protected.get("url"),
                Some(&format!("http://{host}:{port}/acme/new-acct").into())
            );

            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nLocation: abc\r\n\r\n")
                .await?;

            close(stream).await?;

            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let t = spawn(server(listener, host, port));

            let account = Account::load_or_create(
                directory,
                None::<&String>,
                &vec!["mailto:admin@example.com".to_string()],
            )
            .await?;
            assert_eq!(account.kid, "abc");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
    fn new_account(directory: Directory) -> Account {
        let key_pair = EcdsaP256SHA256KeyPair::load(b"0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 \x9e!\xcd\x90u\x8d\xba\xe9\xa0-(S\x86\x9aCt\x9c\xcb\xda6Z2\xb8\x9a\xad\xac\x11\n\xb9J\xcei\xa1D\x03B\x00\x04\x834\xd0\xfb\xff\x83D\xfe\xeb\xabn\xb4$\xf5\xe7\xd0\x11\x1cE\xbfK\xb7\x85ZL\x15'\xdfs\x0c\xfb\xdd\xe5\x97|\x93\xf2g\xbd+\xc8\xd0\xaf\xe0\xc1\x88\x16\x99\xde\x9b\xbb\xe4\xb9`_\xe6=\xe2MLP\xa1Ab").unwrap();
        Account {
            key_pair,
            directory,
            kid: "kid".to_string(),
        }
    }
    #[test]
    fn new_order() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            return_nounce(&listener).await?;
            let (mut stream, _) = listener.accept().await?;
            let mut req: Vec<u8> = vec![0; 1024];
            let r = stream.read(req.as_mut_slice()).await?;
            let (header, payload, _) = parse_req(req[0..r].to_vec());
            let payload = payload.expect("no payload");

            assert!(header.starts_with("POST /acme/new-order HTTP"));

            let i = payload
                .get("identifiers")
                .expect("no identifiers")
                .as_array()
                .expect("no identifiers array")
                .first()
                .expect("no ele")
                .as_object()
                .expect("id not a obj");

            assert_eq!(i.get("type"), Some(&"dns".into()));
            assert_eq!(i.get("value"), Some(&"example.com".into()));

            let body = r##"{"status":"pending", "authorizations": ["http://example.com/auth"], "finalize": "finalize"}"##;

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            close(stream).await?;

            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let t = spawn(server(listener));

            let account = new_account(directory);
            let o = account.new_order(vec!["example.com".to_string()]).await?;

            let (a, f) = match o {
                Order::Pending {
                    authorizations,
                    finalize
                } => (authorizations,
                    finalize),
                _ => panic!("wrong variant")
            };
            assert_eq!(a, vec!["http://example.com/auth".to_string()]);
            assert_eq!(f, "finalize");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
    //fn trigger_challenge () {}
    #[test]
    fn check_auth() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            return_nounce(&listener).await?;
            let (mut stream, _) = listener.accept().await?;
            let mut req: Vec<u8> = vec![0; 1024];
            let r = stream.read(req.as_mut_slice()).await?;

            let (header, payload, _) = parse_req(req[0..r].to_vec());

            assert!(payload.is_none());
            assert!(header.starts_with("POST /check_auth HTTP"));

            let body = r##"{"status":"pending", "challenges": [{"token":"t","type":"tls-alpn-01","url":"http://example.com/bla"}], "identifier": {"type": "dns", "value": "id"}}"##;

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            return_nounce(&listener).await?;
            let (mut stream, _) = listener.accept().await?;
            let mut req: Vec<u8> = vec![0; 1024];
            let r = stream.read(req.as_mut_slice()).await?;

            let (header, payload, _) = parse_req(req[0..r].to_vec());

            assert!(payload.is_none());
            assert!(header.starts_with("POST /check_auth HTTP"));

            let body = r##"{"status":"valid"}"##;

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            close(stream).await?;
            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let auth_url = format!("http://{host}:{port}/check_auth");
            let t = spawn(server(listener));

            let account = new_account(directory);
            let o = account.check_auth(&auth_url).await?;

            let (i, c) = match o {
                Auth::Pending {
                    identifier: Identifier::Dns(i),
                    challenges
                } => (i,
                    challenges),
                _ => panic!("wrong variant")
            };
            assert_eq!(i, "id");
            let Challenge { typ, url, token } = c.first().expect("no challange");
            assert_eq!(*typ, ChallengeType::TlsAlpn01);
            assert_eq!(url, "http://example.com/bla");
            assert_eq!(token, "t");

            let o = account.check_auth(auth_url).await?;

            assert!(matches!(o, Auth::Valid));

            assert!(t.await?, "not cool");
            Ok(())
        });        
    }
    #[test]
    fn send_csr() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            return_nounce(&listener).await?;
            let (mut stream, _) = listener.accept().await?;
            let mut req: Vec<u8> = vec![0; 1024];
            let r = stream.read(req.as_mut_slice()).await?;
            let (header, payload, _) = parse_req(req[0..r].to_vec());
            let payload = payload.expect("no payload");

            assert!(header.starts_with("POST /csr HTTP"));

            let i = payload
                .get("csr")
                .expect("no csr")
                .as_str()
                .expect("csr not str");
            let i = B64_URL_SAFE_NO_PAD
            .decode(i)
            .expect("b64");

            assert_eq!(i, b"csr");

            let body = r##"{"status":"valid", "certificate": "your_cert"}"##;

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            close(stream).await?;

            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let t = spawn(server(listener));

            let account = new_account(directory);
            let o = account.send_csr(format!("http://{host}:{port}/csr"), b"csr".to_vec()).await?;

            let c = match o {
                Order::Valid {
                    certificate
                } => certificate,
                _ => panic!("wrong variant")
            };
            assert_eq!(c, "your_cert");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
}
