use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Cursor, Error},
    sync::Arc,
};

use ring::{
    rand,
    signature::{self, KeyPair},
};
use rustls::internal::msgs::{
    base::PayloadU16,
    handshake::{HandshakePayload, ServerNamePayload},
    message::MessagePayload,
};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{read_one, Item};
use tokio_rustls::TlsAcceptor;
use webpki::DnsName;

use crate::conf::Configuration;

pub fn make_keypair() -> PrivateKey {
    PrivateKey(
        signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rand::SystemRandom::new(),
        )
        .expect("key generation failed")
        .as_ref()
        .to_vec(),
    )
    // let k = signature::EcdsaKeyPair::from_pkcs8(
    //     &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
    //     kp.as_ref(),
    // )
    // .expect("key deserialization failed");
    // k
}

// pub fn self_signed_cert(privkey: PrivateKey) -> Certificate {}

pub fn get_private_key(rd: &mut dyn BufRead) -> Result<Option<Vec<u8>>, Error> {
    loop {
        match read_one(rd)? {
            None => return Ok(None),
            // old shitty format
            Some(Item::RSAKey(key)) => return Ok(Some(key)),
            Some(Item::ECKey(key)) => return Ok(Some(key)),
            // new shitty format
            Some(Item::PKCS8Key(key)) => return Ok(Some(key)),
            _ => {}
        }
    }
}

pub fn acceptors_from_configuration(
    cfg_obj: &Configuration,
) -> Result<HashMap<String, Arc<TlsAcceptor>>, Error> {
    let mut tlses = HashMap::<String, Arc<TlsAcceptor>>::new();
    for tlsname in &cfg_obj.listener.tlses {
        // identify key
        let mcfgkey = if let Some(key) = &cfg_obj.tls[tlsname].key {
            // load key from literal
            log::debug!("loading key from literal");
            Some(PrivateKey(key.as_bytes().to_vec()))
        } else if let Some(key_path) = &cfg_obj.tls[tlsname].key_path {
            // load key from file
            log::debug!("loading key from file");
            if let Some(key) = get_private_key(&mut BufReader::new(File::open(key_path)?))? {
                Some(PrivateKey(key))
            } else {
                None
            }
        } else {
            log::debug!("generating key");
            Some(make_keypair())
        };

        if let None = mcfgkey {
            panic!("missing workable entry for tls config (missing key)");
        }

        // identify certificates
        let mcfgcerts: Option<Vec<Certificate>> = if let Some(_) = &cfg_obj.tls[tlsname].certs {
            log::debug!("NI: loading certs from literal");
            // Some(Vec::<Certificate>::new())
            // Some(
            //     // rustls_pemfile::certs(&mut Cursor::new(certs)).into_iter().map(Certificate).collect()
            //     certs.into_iter().map(Certificate).collect()
            // )

            None
        } else if let Some(certs_path) = &cfg_obj.tls[tlsname].certs_path {
            // load certs from file
            log::debug!("loading certs from file");
            Some(
                rustls_pemfile::certs(&mut BufReader::new(File::open(certs_path)?))?
                    .into_iter()
                    .map(Certificate)
                    .collect(),
            )
        } else {
            None
        };

        if let Some(certs) = &mcfgcerts {
            if certs.is_empty() {
                panic!("missing workable entry for tls config (missing certs)");
            }
        } else {
            panic!("missing workable entry for tls config (missing certs)");
        }

        let tls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                mcfgcerts.expect("missing certs"),
                mcfgkey.expect("missing key"),
            )
            .expect("couldn't initialize TLS config");
        // TODO: client auth and such
        tlses.insert(
            tlsname.clone(),
            Arc::new(TlsAcceptor::from(Arc::new(tls_config))),
        );
    }
    Ok(tlses)
}

pub async fn extract_sni(payload: &MessagePayload) -> Option<(PayloadU16, DnsName)> {
    if let MessagePayload::Handshake(shake) = payload {
        if let HandshakePayload::ClientHello(ohhai) = &shake.payload {
            let sni = ohhai.get_sni_extension();
            if sni.is_none() {
                // No SNI extension
                None
            } else {
                let sni_f = sni.unwrap().first();
                if sni_f.is_none() {
                    // No name indicated
                    None
                } else {
                    if let ServerNamePayload::HostName(hostname) = &sni_f.unwrap().payload {
                        Some(hostname.clone())
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    } else {
        None
    }
}
