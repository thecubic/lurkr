use rustls::internal::msgs::{message::MessagePayload, base::PayloadU16, handshake::{ServerNamePayload, HandshakePayload}};
use webpki::DnsName;

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