use std::{collections::HashMap, sync::Arc};

use regex::Regex;
use rustls::internal::msgs::enums::{AlertDescription, AlertLevel};
use tokio_rustls::TlsAcceptor;

use crate::{
    conf::{Configuration, MappingEntry},
    dispatcher::Dispatcher,
};

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
        // TODO: preserve order feature in config-rs
        for mapping in &cfg_obj.listener.mappings {
            let me: &MappingEntry = &cfg_obj.mapping[mapping];
            if let Some(dispatcher) = Dispatcher::from_mappingentry_tlses(me, tlses.clone()) {
                if me.exact.is_some() && me.matcher.is_some() {
                    panic!(
                        "mapping entry {} cannot have both exact and regex matching",
                        mapping
                    );
                } else if me.exact.is_none() && me.matcher.is_none() {
                    matchers.push(Matcher::UniversalMatcher {
                        rulename: mapping.clone(),
                        dispatcher: dispatcher,
                    });
                } else if let Some(direct) = &me.exact {
                    matchers.push(Matcher::ExactMatcher {
                        rulename: mapping.clone(),
                        exact: direct.clone(),
                        dispatcher: dispatcher,
                    });
                } else if let Some(regex) = &me.matcher {
                    matchers.push(Matcher::RegexMatcher {
                        rulename: mapping.clone(),
                        regex: Regex::new(regex.as_str()).expect(
                            format!("faulty regex {} in mapping {}", regex, mapping).as_str(),
                        ),
                        dispatcher: dispatcher,
                    })
                }
            } else {
                panic!("mapping entry {} is not dispatchable", mapping);
            }
        }
        // the no_mapping handler is just a UniversalMatcher at the end
        matchers.push(match &cfg_obj.listener.no_mapping.as_deref() {
            Some("ignore") => Matcher::UniversalMatcher {
                rulename: "__default".to_string(),
                dispatcher: Dispatcher::NothingDispatcher,
            },
            _ => Matcher::UniversalMatcher {
                rulename: "__default".to_string(),
                dispatcher: Dispatcher::TLSAlertDispatcher {
                    alert_level: AlertLevel::Fatal,
                    // it's a "z" in the standard #gotem
                    alert_description: AlertDescription::UnrecognisedName,
                },
            },
        });
        matchers
    }
}
