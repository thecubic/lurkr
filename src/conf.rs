use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub addr: String,
    pub port: u16,
    pub no_mapping: Option<String>,
    // DEPRECATED: these should be automatic
    pub mappings: Option<Vec<String>>,
    pub tlses: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TLSKeyCertificateEntry {
    // private key
// certificate
}

#[derive(Debug, Deserialize)]
struct TLSKeyCertificatePathEntry {
    // private key path
// certificate path
// reloading interval
}

#[derive(Debug, Deserialize)]
pub struct TlsConfigEntry {
    // key literal or path
    pub key: Option<String>,
    pub key_path: Option<String>,
    pub certs: Option<Vec<Vec<u8>>>,
    pub certs_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub listener: Listener,
    pub mapping: HashMap<String, MappingEntry>,
    pub tls: Option<HashMap<String, TlsConfigEntry>>,
}

#[derive(Debug, Deserialize)]
pub struct MappingEntry {
    // match this by exact SNI
    pub exact: Option<String>,
    // match this by regex
    pub matcher: Option<String>,
    // dispatch this via TCP or wrapped-TLS conn
    pub downstreams: Option<Vec<String>>,
    // when set, terminate upstream TLS
    pub tls: Option<String>,
}
