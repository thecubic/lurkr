use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub addr: String,
    pub port: u16,
    pub no_mapping: Option<String>,
    pub mappings: Vec<String>,
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
struct TlsConfigEntry {
    // key literal or path
    tls_key: Option<String>,
    tls_key_path: Option<String>,
    tls_cert: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub listener: Listener,
    pub mapping: HashMap<String, MappingEntry>,
    // tlses: HashMap<String,
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
    pub tls_config: Option<String>,
}
