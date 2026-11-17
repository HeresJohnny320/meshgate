//! Command-line flags with Go's flag package rules, so every command line
//! that worked with the Go build works here: `-name value`, `--name value`,
//! `-name=value`, bare bool flags, repeatable list flags, parsing stops at
//! the first non-flag argument or `--`.

use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug)]
enum Kind {
    Bool,
    Str,
    Int,
    Dur,
    List,
}

#[derive(Clone, Debug)]
struct Def {
    kind: Kind,
    default: String,
    usage: String,
}

/// A set of flags for one command.
pub struct Flags {
    name: String,
    defs: BTreeMap<String, Def>,
    vals: BTreeMap<String, Vec<String>>,
    set: HashSet<String>,
    args: Vec<String>,
}

impl Flags {
    pub fn new(name: &str) -> Flags {
        Flags { name: name.into(), defs: BTreeMap::new(), vals: BTreeMap::new(), set: HashSet::new(), args: vec![] }
    }

    fn def(&mut self, name: &str, kind: Kind, default: &str, usage: &str) -> &mut Self {
        self.defs.insert(name.into(), Def { kind, default: default.into(), usage: usage.into() });
        self
    }

    pub fn bool(&mut self, name: &str, default: bool, usage: &str) -> &mut Self {
        self.def(name, Kind::Bool, if default { "true" } else { "false" }, usage)
    }
    pub fn str(&mut self, name: &str, default: &str, usage: &str) -> &mut Self {
        self.def(name, Kind::Str, default, usage)
    }
    pub fn int(&mut self, name: &str, default: i64, usage: &str) -> &mut Self {
        self.def(name, Kind::Int, &default.to_string(), usage)
    }
    /// A duration flag ("24h", "90m", "0"), read in seconds.
    pub fn dur(&mut self, name: &str, default: &str, usage: &str) -> &mut Self {
        self.def(name, Kind::Dur, default, usage)
    }
    pub fn list(&mut self, name: &str, usage: &str) -> &mut Self {
        self.def(name, Kind::List, "", usage)
    }

    /// Parses args; on a bad flag prints the error and usage and exits 2
    /// (flag.ExitOnError), on -h/-help prints usage and exits 0.
    pub fn parse(&mut self, args: &[String]) {
        if let Err(e) = self.try_parse(args) {
            if e == "help" {
                self.usage();
                std::process::exit(0);
            }
            eprintln!("{e}");
            self.usage();
            std::process::exit(2);
        }
    }

    pub fn try_parse(&mut self, args: &[String]) -> Result<(), String> {
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a.len() < 2 || !a.starts_with('-') {
                break;
            }
            if a == "--" {
                i += 1;
                break;
            }
            let body = a.strip_prefix("--").unwrap_or(&a[1..]);
            if body.is_empty() || body.starts_with('-') || body.starts_with('=') {
                return Err(format!("bad flag syntax: {a}"));
            }
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (body.to_string(), None),
            };
            let Some(def) = self.defs.get(&name).cloned() else {
                if name == "h" || name == "help" {
                    return Err("help".into());
                }
                return Err(format!("flag provided but not defined: -{name}"));
            };
            let value = match (&def.kind, inline) {
                (Kind::Bool, Some(v)) => {
                    parse_bool(&v).ok_or_else(|| format!("invalid boolean value {v:?} for -{name}: parse error"))?;
                    v
                }
                (Kind::Bool, None) => "true".into(),
                (_, Some(v)) => v,
                (_, None) => {
                    i += 1;
                    args.get(i).cloned().ok_or_else(|| format!("flag needs an argument: -{name}"))?
                }
            };
            match def.kind {
                Kind::Int => {
                    crate::gojson::atoi(&value).ok_or_else(|| format!("invalid value {value:?} for flag -{name}: parse error"))?;
                }
                Kind::Dur => {
                    parse_duration(&value).ok_or_else(|| format!("invalid value {value:?} for flag -{name}: parse error"))?;
                }
                _ => {}
            }
            let e = self.vals.entry(name.clone()).or_default();
            if matches!(def.kind, Kind::List) {
                e.push(value);
            } else {
                *e = vec![value];
            }
            self.set.insert(name);
            i += 1;
        }
        self.args = args[i..].to_vec();
        Ok(())
    }

    fn raw(&self, name: &str) -> String {
        self.vals
            .get(name)
            .and_then(|v| v.last().cloned())
            .unwrap_or_else(|| self.defs.get(name).map(|d| d.default.clone()).unwrap_or_default())
    }

    pub fn get_bool(&self, name: &str) -> bool {
        parse_bool(&self.raw(name)).unwrap_or(false)
    }
    pub fn get_str(&self, name: &str) -> String {
        self.raw(name)
    }
    pub fn get_int(&self, name: &str) -> i64 {
        crate::gojson::atoi(&self.raw(name)).unwrap_or(0)
    }
    /// Seconds.
    pub fn get_dur(&self, name: &str) -> i64 {
        parse_duration(&self.raw(name)).unwrap_or(0)
    }
    pub fn get_list(&self, name: &str) -> Vec<String> {
        self.vals.get(name).cloned().unwrap_or_default()
    }

    /// Whether the flag was given on the command line (flag.Visit).
    pub fn explicit(&self, name: &str) -> bool {
        self.set.contains(name)
    }

    pub fn arg(&self, i: usize) -> String {
        self.args.get(i).cloned().unwrap_or_default()
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// flag.PrintDefaults.
    pub fn usage(&self) {
        eprintln!("Usage of {}:", self.name);
        for (n, d) in &self.defs {
            let ty = match d.kind {
                Kind::Bool => "",
                Kind::Str => " string",
                Kind::Int => " int",
                Kind::Dur => " duration",
                Kind::List => " value",
            };
            let mut line = format!("  -{n}{ty}\n    \t{}", d.usage);
            let show = match d.kind {
                Kind::Bool => d.default == "true",
                Kind::Str => !d.default.is_empty(),
                Kind::Int => d.default != "0",
                Kind::Dur => d.default != "0",
                Kind::List => false,
            };
            if show {
                if matches!(d.kind, Kind::Str) {
                    line.push_str(&format!(" (default {:?})", d.default));
                } else {
                    line.push_str(&format!(" (default {})", d.default));
                }
            }
            eprintln!("{line}");
        }
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// time.ParseDuration in whole seconds ("0" allowed).
pub fn parse_duration(s: &str) -> Option<i64> {
    if s == "0" {
        return Some(0);
    }
    let (neg, body) = match s.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = crate::history::parse_duration(body)?;
    Some(if neg { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn go_style() {
        let mut f = Flags::new("join");
        f.str("kind", "", "").bool("y", false, "").int("port", 51820, "").list("route", "").dur("ttl", "24h", "");
        f.try_parse(&args("--kind client -y -port=51830 -route 10.0.0.0/8 --route=192.168.1.0/24 tok extra -z")).unwrap();
        assert_eq!(f.get_str("kind"), "client");
        assert!(f.get_bool("y"));
        assert_eq!(f.get_int("port"), 51830);
        assert!(f.explicit("port") && !f.explicit("ttl"));
        assert_eq!(f.get_list("route"), ["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(f.get_dur("ttl"), 86400);
        assert_eq!(f.args(), ["tok", "extra", "-z"]);
        let mut g = Flags::new("x");
        g.bool("y", false, "");
        assert!(g.try_parse(&args("-nope")).is_err());
        assert!(g.try_parse(&args("-y=maybe")).is_err());
        let mut h = Flags::new("x");
        h.str("name", "", "");
        assert!(h.try_parse(&args("-name")).is_err());
        assert_eq!(parse_duration("1h30m"), Some(5400));
        assert_eq!(parse_duration("0"), Some(0));
    }
}
