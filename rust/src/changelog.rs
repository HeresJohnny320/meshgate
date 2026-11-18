//! The changelog shown in the UIs (shared with the Go build). Lines start
//! with "+" (added), "-" (removed) or "~" (changed or fixed); "## " starts a
//! version.

pub const TEXT: &str = include_str!(concat!(env!("MESHGATE_GO_DIR"), "/internal/changelog/CHANGELOG.md"));
