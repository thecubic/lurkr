use std::{collections::HashMap, sync::Arc};

use rcgen::generate_simple_self_signed;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::{server::WebPkiClientVerifier, RootCertStore};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use rustls_pki_types::pem::PemObject;
use tokio_rustls::TlsAcceptor;

use anyhow::{anyhow, Error, Result};

use crate::conf::{Configuration, TlsConfigEntry};

pub fn acceptors_from_configuration(
    cfg_obj: &Configuration,
) -> anyhow::Result<HashMap<String, Arc<TlsAcceptor>>, Error> {
    let mut tlses = HashMap::<String, Arc<TlsAcceptor>>::new();
    // if-present, iterate over config-present tls specification sections
    if let Some(tlscfgs) = &cfg_obj.tls {
        for (tlsname, tlsspec) in tlscfgs.iter() {
            log::debug!("building tlsspec {}", tlsname);

            let to_generate = tlsspec.certs.is_none() && tlsspec.certs_path.is_none();
            let identity_key: PrivateKeyDer<'static>;
            let identity_certs: Vec<CertificateDer<'static>>;
            if to_generate {
                let ck = generate_simple_self_signed(vec!["localhost".to_string()])?;
                identity_certs = vec![ck.cert.der().to_owned()];
                identity_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(Vec::from(
                    ck.signing_key.serialized_der(),
                )));
            } else {
                identity_key = load_key_from_tlsspec(&tlsspec)?;
                identity_certs = server_certificates(&tlsspec)?;
            }

            if identity_certs.is_empty() {
                panic!("missing workable entry for tls config (missing certs)");
            }

            // to make sure it explodes if unsupported
            let _signing_key = any_supported_type(&identity_key).expect("unsupported key");

            // Client auth certificates
            let is_clientrequested =
                tlsspec.client_certbundle.is_some() || tlsspec.client_certbundle_path.is_some();
            let ccfgcerts = client_certificates(&tlsspec)?;

            let client_auth = if is_clientrequested {
                let mut roots = RootCertStore::empty();
                roots.add_parsable_certificates(ccfgcerts);
                if roots.is_empty() {
                    log::debug!("requested client auth with empty trust roots. sus");
                    // lmao rustls is trying to save us from ourselves
                    // but guess what we WANT to be stupid sometimes
                    roots.add(
                        generate_simple_self_signed(vec!["example.com".into()])?
                            .cert
                            .der()
                            .to_owned(),
                    )?;
                }
                if tlsspec.require_client_auth == Some(true) {
                    // only allow proven connections
                    WebPkiClientVerifier::builder(roots.into()).build()?
                } else {
                    WebPkiClientVerifier::builder(roots.into())
                        .allow_unauthenticated()
                        .build()?
                }
            } else {
                WebPkiClientVerifier::no_client_auth()
            };

            let tls_config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(identity_certs, identity_key.clone_key())?;
            tlses.insert(
                tlsname.clone(),
                Arc::new(TlsAcceptor::from(Arc::new(tls_config))),
            );
        }
    }
    Ok(tlses)
}

pub fn load_key_from_tlsspec(tlsspec: &TlsConfigEntry) -> Result<PrivateKeyDer<'static>, Error> {
    if let Some(key) = &tlsspec.key {
        log::debug!("loading key from literal");
        Ok(PrivateKeyDer::from_pem_slice(key.as_bytes())?.clone_key())
    } else if let Some(key_path) = &tlsspec.key_path {
        log::debug!("loading key from file");
        Ok(PrivateKeyDer::from_pem_file(key_path)?.clone_key())
    } else {
        Err(anyhow!("tls spec did not fill out either key type"))
    }
}

pub fn server_certificates(
    tlsspec: &TlsConfigEntry,
) -> Result<Vec<CertificateDer<'static>>, Error> {
    if let Some(certliteral) = &tlsspec.certs {
        log::debug!("NI: loading certs from literal");
        Ok(CertificateDer::pem_slice_iter(certliteral.as_bytes())
            .map(|cert| cert.unwrap().into_owned())
            .collect())
    } else if let Some(certs_path) = &tlsspec.certs_path {
        // load certs from file
        log::debug!("loading certs from file");
        Ok(CertificateDer::pem_file_iter(certs_path)
            .unwrap()
            .map(|cert| cert.unwrap().into_owned())
            .collect())
    } else {
        Ok(vec![])
    }
}

pub fn client_certificates(tlsspec: &TlsConfigEntry) -> Result<Vec<CertificateDer<'_>>, Error> {
    if let Some(inlinebundle) = &tlsspec.client_certbundle {
        log::debug!("loading client cert trust bundle from literal");
        Ok(CertificateDer::pem_slice_iter(inlinebundle.as_bytes())
            .map(|cert| cert.unwrap())
            .collect())
    } else if let Some(certbundle_path) = &tlsspec.client_certbundle_path {
        if certbundle_path.is_empty() {
            log::debug!("emptypath skip");
            return Ok(vec![]);
        }
        log::debug!("loading client cert trust bundle from file");
        Ok(CertificateDer::pem_file_iter(certbundle_path)
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect())
    } else {
        log::debug!("no client file or literal: okay");
        Ok(vec![])
    }
}
