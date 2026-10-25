use indexmap::IndexMap;
use serde_derive::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub listener: Listener,
    // order preservation must be here otherwise the rules match in random order
    // this is a PITA while developing but also very funny
    pub mapping: IndexMap<String, MappingEntry>,
    pub tls: Option<HashMap<String, TlsConfigEntry>>,
}

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfigEntry {
    // key literal or path
    pub key: Option<String>,
    pub key_path: Option<String>,
    // Service (identity) side
    pub certs: Option<String>,
    pub certs_path: Option<String>,
    // Client (authproof) side
    pub require_client_auth: Option<bool>,
    pub client_certbundle: Option<String>,
    pub client_certbundle_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingEntry {
    // SNI matching criteria; the rule matches if any criterion matches.
    // At least one must be given.

    // exact string match against each entry, in order
    pub names: Option<Vec<String>>,

    // regex match against each entry, in order
    pub regexes: Option<Vec<String>>,

    // matches everything; definitely put universal rules last in the config
    pub universal: Option<bool>,

    // dispatch this via TCP or wrapped-TLS conn
    pub downstreams: Option<Vec<String>>,

    // when set, terminate TLS with this config
    pub tls: Option<String>,

    // HTTPS response
    pub response_code: Option<u16>,

    // #[allow(dead_code)]
    pub response_body: Option<String>,
}
