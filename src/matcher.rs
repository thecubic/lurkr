use regex::Regex;
use rustls::AlertDescription;
use rustls::internal::msgs::enums::AlertLevel;

use crate::dispatcher::Dispatcher;

// A single matcher type; a rule matches the requested SNI when any of
// its criteria match. Criteria are attempted cheapest-first:
// every entry of names (exact equality), then every entry of regexes,
// then universal.
#[derive(Debug)]
pub struct Matcher {
    pub rulename: String,
    pub dispatcher: Dispatcher,
    pub names: Vec<String>,
    pub regexes: Vec<Regex>,
    pub universal: bool,
}

impl Matcher {
    // Returns a short description of what matched, or None
    pub fn matches(&self, indicated: &str) -> Option<String> {
        if let Some(name) = self.names.iter().find(|n| n.as_str() == indicated) {
            return Some(format!("name {}", name));
        }
        if let Some(regex) = self.regexes.iter().find(|r| r.is_match(indicated)) {
            return Some(format!("regex {}", regex.as_str()));
        }
        if self.universal {
            return Some("universal".to_string());
        }
        None
    }

    // Matchers define the SNI-to-execution mapping
    pub fn from_configuration() -> Vec<Matcher> {
        let mut matchers = Vec::<Matcher>::new();
        for (mapname, mapspec) in crate::FULLCFG.mapping.iter() {
            tracing::debug!("assembling mapping {}", mapname);
            let Some(dispatcher) = Dispatcher::from_mappingentry(mapspec) else {
                panic!("mapping entry {} is not dispatchable", mapname);
            };
            if mapspec.names.as_ref().is_some_and(|n| n.is_empty()) {
                panic!("mapping entry {} has an empty names list", mapname);
            }
            if mapspec.regexes.as_ref().is_some_and(|r| r.is_empty()) {
                panic!("mapping entry {} has an empty regexes list", mapname);
            }
            let names = mapspec.names.clone().unwrap_or_default();
            let regexes: Vec<Regex> = mapspec
                .regexes
                .iter()
                .flatten()
                .map(|r| {
                    Regex::new(r).unwrap_or_else(|e| {
                        panic!("faulty regex {} in mapping {}: {}", r, mapname, e)
                    })
                })
                .collect();
            let universal = mapspec.universal.unwrap_or(false);
            if !universal && names.is_empty() && regexes.is_empty() {
                panic!(
                    "mapping entry {} has no matching criteria (names, regexes, or universal = true)",
                    mapname
                );
            }
            if universal && !(names.is_empty() && regexes.is_empty()) {
                tracing::warn!(
                    "mapping entry {} is universal; its names/regexes are redundant",
                    mapname
                );
            }
            matchers.push(Matcher {
                rulename: mapname.clone(),
                dispatcher,
                names,
                regexes,
                universal,
            });
        }
        // we give you one free TLS unrecognized-name
        // dispatching universal matcher at the end
        matchers.push(Matcher {
            rulename: "__default".to_string(),
            dispatcher: Dispatcher::TLSAlertDispatcher {
                alert_level: AlertLevel::Fatal,
                // it's a "z" in the standard #gotem
                alert_description: AlertDescription::UnrecognisedName,
            },
            names: vec![],
            regexes: vec![],
            universal: true,
        });
        matchers
    }
}
