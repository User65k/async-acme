use std::time::{Duration, SystemTime};
use base64::Engine;
use generic_async_http_client::Request;
use x509_parser::{der_parser::oid, prelude::{ParsedExtension, X509Certificate}};
use serde::Deserialize;
use serde::de::{Deserializer, Visitor, MapAccess};

use crate::{B64_URL_SAFE_NO_PAD, sleep};


pub async fn try_ari(uri: &str, cert: &X509Certificate<'_>) -> Option<Duration> {
    let mut full_uri = String::with_capacity(uri.len()+128);
    full_uri.push_str(uri);
    if !uri.ends_with('/') {
        full_uri.push('/');
    }
    let uid = get_unique_identifier(cert)?;
    full_uri.push_str(&uid);
    let mut err_cnt = 0;
    loop {
        let mut resp = match Request::get(&full_uri).exec().await {
            Ok(resp) => {
                match resp.status_code() {
                    200 => resp,
                    500..600 if err_cnt < 10 => {
                        // Temporary error
                        sleep(Duration::from_secs(1 << err_cnt)).await;
                        err_cnt += 1;
                        continue;
                    },
                    _ => {
                        // Long term errors
                        return None;
                    }
                }
            },
            Err(e) => {
                // Temporary error
                if err_cnt > 10 {return None;}
                sleep(Duration::from_secs(1 << err_cnt)).await;
                err_cnt += 1;
                continue;
            }
        };
        let ri: RenewalInfo = resp.json().await.ok()?;
        if let Some(reason) = ri.explanation_url {
            log::info!("ARI window reasoning: {}", reason);
        }

        let earliest = match ri.suggested_window.start.duration_since(SystemTime::now()) {
            Ok(time_in_future) => time_in_future,
            _ => {
                //time is in the past, attempt renewal immediately.
                return Some(Duration::ZERO);
            }
        };

        if let Some(retry) = resp.header("Retry-After")
            .and_then(|h| std::str::from_utf8(h.as_ref()).ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            let retry_after = Duration::from_secs(retry.max(60));
            if retry_after < earliest {
                log::trace!("Received Retry-After header, waiting {retry} seconds...");
                sleep(retry_after).await;
                continue;
            }
        }
        break Some(earliest);
    }
}

#[cfg(feature="ari")]
#[derive(Debug, Clone, Deserialize)]
struct RenewalInfo {
    #[serde(rename = "suggestedWindow")]
    suggested_window: RenewalInfoWindow,
    #[serde(rename = "explanationURL")]
    explanation_url: Option<String>,
}
#[cfg(feature="ari")]
#[derive(Debug, Clone)]
struct RenewalInfoWindow {
    start: SystemTime,
    end: SystemTime
}
/// The "renewalInfo" Resource https://www.ietf.org/archive/id/draft-ietf-acme-ari-07.html#name-the-renewalinfo-resource
fn get_unique_identifier(cert: &X509Certificate) -> Option<String> {
    let mut ret = String::with_capacity(128);
    let aki = cert.get_extension_unique(&oid!(2.5.29.35)).ok()??.parsed_extension();
    match aki {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            B64_URL_SAFE_NO_PAD.encode_string(aki.key_identifier.as_ref()?.0, &mut ret)
        },
        _ => return None
    }
    ret.push('.');
    let mut s = cert.serial.to_bytes_be();
    match s.first() {
        Some(v) if *v > 0x7f => s.insert(0, 0),
        _ => {}
    }
    B64_URL_SAFE_NO_PAD.encode_string(s, &mut ret);
    Some(ret)
}


impl<'de> Deserialize<'de> for RenewalInfoWindow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Start, End }

        struct RenewalInfoWindowVisitor;

        impl<'de> Visitor<'de> for RenewalInfoWindowVisitor {
            type Value = RenewalInfoWindow;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("rfc3339 date")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RenewalInfoWindow, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut ret = RenewalInfoWindow {
                    start: SystemTime::UNIX_EPOCH,
                    end: SystemTime::UNIX_EPOCH
                };
                while let Some(key) = map.next_key()? {
                    let v = match key {
                        Field::Start => {
                            &mut ret.start
                        }
                        Field::End => {
                            &mut ret.end
                        }
                    };
                    *v = humantime::parse_rfc3339(map.next_value()?).map_err(|e|serde::de::Error::custom(e))?;
                }
                Ok(ret)
            }
        }

        const FIELDS: &[&str] = &["start", "end"];
        deserializer.deserialize_struct("RenewalInfoWindow", FIELDS, RenewalInfoWindowVisitor)
    }
}

/*
#[test]
fn gen_cert() {
    let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.serial_number = Some(SerialNumber::from_slice(&[0,0x87,0x65,0x43,0x21]));
    params.use_authority_key_identifier_extension = true;
    let kp = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let der = params.self_signed(&kp).unwrap();
    print!("{}", der.pem());
} */

#[cfg(test)]
#[cfg(any(feature = "use_async_std", feature = "use_tokio"))]
mod test {
    use super::*;
    use crate::test::*;

    #[test]
    fn gen_ari_link(){
        let cert = b"0\x82\x0100\x81\xd6\xa0\x03\x02\x01\x02\x02\x05\x00\x87eC!0\n\x06\x08*\x86H\xce=\x04\x03\x020\x000 \x17\r750101000000Z\x18\x0f40960101000000Z0\x000Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04{]\xd6\xac\xc8\xb3\xa0(}\xea\xa2\xb6\xde}OF\x0bmz\x84\x0c\xf7\xc9\xf0\x9a\xf7\xf1S\xf0t@\xc9\x8cF\x82\xfa\xb0\xec\xa9>\x1b\x18J\xc5B\xc1\x0c\x00\xf0\xc8\xa5Y\x03\x91Z=$\x91\x16|S\x81\xfb,\xa3;090\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\x86\xfc\x03\xf4\x81\x0bn.\xb0\x03\"\xd7\xe7\xb0\x1b\x0f\xbb\x14\x91_0\x16\x06\x03U\x1d\x11\x04\x0f0\r\x82\x0bexample.com0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03I\x000F\x02!\x00\xaa\xc8\x98\xe3\xfc/\xf4}\xbfZ\xd3\xe3\xdbK\xd5\x90~\x19\xff\x17Y\xa2\x13\xdbB\x8ek<r\xb1\xc8\xcc\x02!\x00\xe6\x082\xe6\xbd1\xef\xba\x82\xe4~\xa0\xc4{\xa1\xadP\x80\xed\xae\xcd5=Hw\xd0j\x04\xfa\xb8\x06C";
        /*
        Serial:
        87:65:43:21
        Authority Key Identifier:
        86:FC:03:F4:81:0B:6E:2E:B0:03:22:D7:E7:B0:1B:0F:BB:14:91:5F
        */
        let (_, cert) = x509_parser::parse_x509_certificate(cert).unwrap();
        assert_eq!(get_unique_identifier(&cert).as_deref(), Some("hvwD9IELbi6wAyLX57AbD7sUkV8.AIdlQyE"));
    }
    #[test]
    fn parse(){
        let json = r##"{
            "start": "2021-01-03T00:00:00Z",
            "end": "2021-01-07T00:00:00Z"
        }"##;
        let riw: RenewalInfoWindow = serde_json::from_str(json).unwrap();
        let su = riw.start.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let eu = riw.end.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(su, 1609632000);
        assert_eq!(eu, 1609977600);
    }
    #[test]
    fn discover_ari() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            let (mut stream, _) = listener.accept().await?;
            assert_stream(&mut stream, b"GET /directory HTTP").await?;

            let body = format!(
                r##"{{
                "keyChange": "host/key-change",
                "meta": {{
                "caaIdentities": [
                    "letsencrypt.org"
                ],
                "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf",
                "website": "https://letsencrypt.org/docs/staging-environment/"
                }},
                "newAccount": "host/new-acct",
                "newNonce": "host/new-nonce",
                "newOrder": "host/new-order",
                "q3Eo-_fidjY": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
                "revokeCert": "host/revoke-cert",
                "renewalInfo": "host/ari"
            }}"##
            );

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;


            let (mut stream, _) = listener.accept().await?;
            assert_stream(&mut stream, b"GET /directory HTTP").await?;

            let body = format!(
                r##"{{
                "keyChange": "host/key-change",
                "meta": {{
                    "caaIdentities": [
                    "letsencrypt.org"
                    ],
                    "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf",
                    "website": "https://letsencrypt.org/docs/staging-environment/"
                }},
                "newAccount": "host/new-acct",
                "newNonce": "host/new-nonce",
                "newOrder": "host/new-order",
                "q3Eo-_fidjY": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
                "revokeCert": "host/revoke-cert"
                }}"##
            );

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let t = spawn(server(listener));

            let d = Directory::discover(&format!("http://{}:{}/directory", host, port)).await?;
            assert_eq!(d.new_account, "host/new-acct");
            assert_eq!(d.new_nonce, "host/new-nonce");
            assert_eq!(d.new_order, "host/new-order");
            assert_eq!(d.renewal_info.as_ref().map(|s|s.as_str()), Some("host/ari"));


            let d = Directory::discover(&format!("http://{}:{}/directory", host, port)).await?;
            assert_eq!(d.new_account, "host/new-acct");
            assert_eq!(d.new_nonce, "host/new-nonce");
            assert_eq!(d.new_order, "host/new-order");
            assert_eq!(d.renewal_info, None);

            assert!(t.await?, "not cool");
            Ok(())
        });
    }

}