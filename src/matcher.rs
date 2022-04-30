use regex::Regex;

use crate::dispatcher::Dispatcher;

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
