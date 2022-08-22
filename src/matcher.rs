use std::{collections::HashMap, sync::Arc};

use regex::Regex;
use rustls::internal::msgs::enums::{AlertDescription, AlertLevel};
use tokio_rustls::TlsAcceptor;

use crate::{conf::Configuration, dispatcher::Dispatcher};

#[derive(Debug)]
pub enum Matcher {
    ExactMatcher {
        rulename: String,
        dispatcher: Dispatcher,
        // determinant for this type
        exact: String,
    },
    RegexMatcher {
        rulename: String,
        dispatcher: Dispatcher,
        // determinant for this type
        regex: Regex,
    },
    UniversalMatcher {
        rulename: String,
        dispatcher: Dispatcher,
        // "isn't anything else" determinant
    },
}

impl Matcher {
    // Matchers define the SNI-to-execution mapping
    pub fn from_configuration_tlses(
        cfg_obj: &Configuration,
        tlses: Arc<HashMap<String, Arc<TlsAcceptor>>>,
    ) -> Vec<Matcher> {
        let mut matchers = Vec::<Matcher>::new();
        // TODO: ordering? weights? preserve order feature in config-rs?
        for (mapname, mapspec) in cfg_obj.mapping.iter() {
            log::debug!("assembling mapping {}", mapname);
            if let Some(dispatcher) = Dispatcher::from_mappingentry_tlses(&mapspec, tlses.clone()) {
                if mapspec.exact.is_some() && mapspec.regex.is_some() {
                    panic!(
                        "mapping entry {} cannot have both exact and regex matching",
                        mapname
                    );
                } else if mapspec.exact.is_none() && mapspec.regex.is_none() {
                    matchers.push(Matcher::UniversalMatcher {
                        rulename: mapname.clone(),
                        dispatcher: dispatcher,
                    });
                } else if let Some(direct) = &mapspec.exact {
                    matchers.push(Matcher::ExactMatcher {
                        rulename: mapname.clone(),
                        exact: direct.clone(),
                        dispatcher: dispatcher,
                    });
                } else if let Some(regex) = &mapspec.regex {
                    matchers.push(Matcher::RegexMatcher {
                        rulename: mapname.clone(),
                        regex: Regex::new(regex.as_str()).expect(
                            format!("faulty regex {} in mapping {}", regex, mapname).as_str(),
                        ),
                        dispatcher: dispatcher,
                    })
                }
            } else {
                panic!("mapping entry {} is not dispatchable", mapname);
            }
        }
        // we give you one free TLS unrecognized-name
        // dispatching UniversalMatcher at the end
        matchers.push(Matcher::UniversalMatcher {
            rulename: "__default".to_string(),
            dispatcher: Dispatcher::TLSAlertDispatcher {
                alert_level: AlertLevel::Fatal,
                // it's a "z" in the standard #gotem
                alert_description: AlertDescription::UnrecognisedName,
            },
        });
        matchers
    }
}
