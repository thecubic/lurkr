use indexmap::IndexMap;
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
pub struct MappingEntry {
    // SNI matching is one of 3 handlings:

    // ExactMatcher does exact string matching on "exact" field
    pub exact: Option<String>,

    // RegexMatcher does regex string matching on "regex" field
    pub regex: Option<String>,

    // Without "exact" or "regex", the matcher is universal
    // definitely put UniversalMatcher last in the config

    // dispatch this via TCP or wrapped-TLS conn
    pub downstreams: Option<Vec<String>>,

    // when set, terminate TLS with this config
    pub tls: Option<String>,

    // HTTPS response
    pub response_code: Option<u16>,
    pub response_body: Option<String>,
}
