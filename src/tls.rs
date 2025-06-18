use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Error},
    sync::Arc,
};

use ring::{rand, signature};
use rustls::{
    internal::msgs::{
        base::PayloadU16,
        handshake::{HandshakePayload, ServerNamePayload},
        message::MessagePayload,
    },
    server::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth},
    sign::any_supported_type,
    RootCertStore,
};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{read_one, Item};
use tokio_rustls::TlsAcceptor;
use webpki::DnsName;

use rcgen::{
    Certificate as RcCertificate, CertificateParams as RcCertificateParams, DistinguishedName,
    KeyPair as RcKeyPair,
};

use anyhow::Result;

use crate::conf::{Configuration, TlsConfigEntry};

// generate an ECDSA keypair for the not-provided case
pub fn make_ecdsa_keypair() -> PrivateKey {
    PrivateKey(
        signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rand::SystemRandom::new(),
        )
        .expect("key generation failed")
        .as_ref()
        .to_vec(),
    )
}

pub fn self_signed_cert(privkey: &PrivateKey) -> RcCertificate {
    let mut params = RcCertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.key_pair = Some(RcKeyPair::from_der(&privkey.0).expect("couldn't load key"));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ephemeral");
    RcCertificate::from_params(params).expect("couldn't generate self-signed certificate")
}

// Returns the DER-vector of the first private key found via the reader
pub fn get_private_key(rd: &mut dyn BufRead) -> Result<Option<Vec<u8>>, Error> {
    loop {
        match read_one(rd)? {
            None => return Ok(None),
            // old shitty format bound to a particular key style
            // stop using these, I beg you
            // looking at you, CloudFlare
            Some(Item::RSAKey(key)) => return Ok(Some(key)),
            Some(Item::ECKey(key)) => return Ok(Some(key)),
            // new format
            Some(Item::PKCS8Key(key)) => return Ok(Some(key)),
            _ => {}
        }
    }
}

pub fn acceptors_from_configuration(
    cfg_obj: &Configuration,
) -> Result<HashMap<String, Arc<TlsAcceptor>>, Error> {
    let mut tlses = HashMap::<String, Arc<TlsAcceptor>>::new();
    // if-present, iterate over config-present tls specification sections
    if let Some(tlscfgs) = &cfg_obj.tls {
        for (tlsname, tlsspec) in tlscfgs.iter() {
            log::debug!("building tlsspec {}", tlsname);

            // identity key
            let identity_key =
                load_key_from_tlsspec(&tlsspec).expect("missing private key configuration");

            // Server's certificate
            let is_selfsigned = tlsspec.certs.is_none() && tlsspec.certs_path.is_none();
            let identity_certs = if is_selfsigned {
                log::debug!("no file or literal: self-signed cert");
                Ok(make_selfsigned_cert(&identity_key))
            } else {
                server_certificates(&tlsspec)
            }?;
            if identity_certs.is_empty() {
                panic!("missing workable entry for tls config (missing certs)");
            }

            // to make sure it explodes if unsupported
            let _signing_key = any_supported_type(&identity_key).expect("unsupported key");

            // Client auth certificates
            let is_clientrequested =
                tlsspec.client_certbundle.is_some() || tlsspec.client_certbundle_path.is_some();
            let ccfgcerts = client_certificates(&tlsspec)?;
            let cverifier = if is_clientrequested {
                let mut roots = RootCertStore::empty();
                for cert in ccfgcerts.iter() {
                    roots.add(cert).ok();
                }
                if tlsspec.require_client_auth == Some(true) {
                    // only allow proven connections
                    AllowAnyAuthenticatedClient::new(roots)
                } else {
                    // ask, but allow proven or unproven connections
                    AllowAnyAnonymousOrAuthenticatedClient::new(RootCertStore::empty())
                }
            } else {
                // do not ask
                NoClientAuth::new()
            };

            let tls_config = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(cverifier)
                .with_single_cert(identity_certs, identity_key)
                .expect("couldn't initialize TLS config");

            tlses.insert(
                tlsname.clone(),
                Arc::new(TlsAcceptor::from(Arc::new(tls_config))),
            );
        }
    }
    Ok(tlses)
}

pub fn load_key_from_tlsspec(tlsspec: &TlsConfigEntry) -> Option<PrivateKey> {
    if let Some(key) = &tlsspec.key {
        log::debug!("loading key from literal");
        match rustls_pemfile::pkcs8_private_keys(&mut key.as_bytes()) {
            Err(_) => None,
            Ok(keyvecvec) => match keyvecvec.first() {
                None => None,
                Some(keyblob) => Some(PrivateKey(keyblob.clone())),
            },
        }
    } else if let Some(key_path) = &tlsspec.key_path {
        log::debug!("loading key from file");
        match get_private_key(&mut BufReader::new(
            File::open(key_path).expect("couldn't open key_path file"),
        )) {
            Err(_) => None,
            Ok(None) => None,
            Ok(Some(keyblob)) => Some(PrivateKey(keyblob.clone())),
        }
    } else {
        log::debug!("generating key");
        Some(make_ecdsa_keypair())
    }
}

pub fn server_certificates(tlsspec: &TlsConfigEntry) -> Result<Vec<Certificate>, Error> {
    if let Some(certliteral) = &tlsspec.certs {
        log::debug!("NI: loading certs from literal");
        Ok(rustls_pemfile::certs(&mut certliteral.as_bytes())?
            .into_iter()
            .map(Certificate)
            .collect())
    } else if let Some(certs_path) = &tlsspec.certs_path {
        // load certs from file
        log::debug!("loading certs from file");
        Ok(
            rustls_pemfile::certs(&mut BufReader::new(File::open(certs_path)?))?
                .into_iter()
                .map(Certificate)
                .collect(),
        )
    } else {
        Ok(vec![])
    }
}
pub fn make_selfsigned_cert(mykey: &PrivateKey) -> Vec<Certificate> {
    vec![Certificate(
        self_signed_cert(&mykey).serialize_der().unwrap(),
    )]
}

pub fn client_certificates(tlsspec: &TlsConfigEntry) -> Result<Vec<Certificate>, Error> {
    if let Some(inlinebundle) = &tlsspec.client_certbundle {
        log::debug!("loading client cert trust bundle from literal");
        let certs = rustls_pemfile::certs(&mut BufReader::new(inlinebundle.as_bytes()))?
            .into_iter()
            .map(Certificate)
            .collect();
        Ok(certs)
    } else if let Some(certbundle_path) = &tlsspec.client_certbundle_path {
        if certbundle_path.is_empty() {
            log::debug!("emptypath skip");
            return Ok(vec![]);
        }
        log::debug!("loading client cert trust bundle from file");
        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(certbundle_path)?))?
            .into_iter()
            .map(Certificate)
            .collect();
        Ok(certs)
    } else {
        log::debug!("no client file or literal: okay");
        Ok(vec![])
    }
}

pub async fn extract_sni(payload: &MessagePayload) -> Option<(PayloadU16, DnsName)> {
    if let MessagePayload::Handshake { parsed, .. } = payload {
        if let HandshakePayload::ClientHello(ohhai) = &parsed.payload {
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
