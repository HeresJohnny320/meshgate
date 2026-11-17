//! Prompts: lines, yes/no and hidden passwords.

use std::io::{BufRead, Write};

pub fn read_line() -> String {
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s
}

/// Asks with a default shown in brackets.
pub fn ask(prompt: &str, def: &str) -> String {
    if def.is_empty() {
        print!("{prompt}: ");
    } else {
        print!("{prompt} [{def}]: ");
    }
    let _ = std::io::stdout().flush();
    let line = read_line().trim().to_string();
    if line.is_empty() { def.to_string() } else { line }
}

pub fn ask_yes(prompt: &str, def: bool) -> bool {
    let d = if def { "Y/n" } else { "y/N" };
    let a = ask(&format!("{prompt} ({d})"), "").to_lowercase();
    if a.is_empty() { def } else { a.starts_with('y') }
}

pub fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Reads a line without echo.
#[cfg(unix)]
pub fn read_password() -> String {
    // SAFETY: termios calls on stdin with a zeroed struct filled by tcgetattr.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        let ok = libc::tcgetattr(0, &mut t) == 0;
        let old = t;
        if ok {
            t.c_lflag &= !libc::ECHO;
            t.c_lflag |= libc::ICANON;
            libc::tcsetattr(0, libc::TCSANOW, &t);
        }
        let s = read_line();
        if ok {
            libc::tcsetattr(0, libc::TCSANOW, &old);
        }
        s.trim_end_matches(['\r', '\n']).to_string()
    }
}

#[cfg(windows)]
pub fn read_password() -> String {
    crate::winnet::read_password()
}

/// Asks for a password twice (at least 8 characters).
pub fn ask_password(prompt: &str) -> Result<String, String> {
    if !stdin_is_terminal() {
        return Err("no terminal for the password prompt; pass --admin-pass".into());
    }
    loop {
        print!("{prompt}: ");
        let _ = std::io::stdout().flush();
        let p = read_password();
        print!("\nRepeat: ");
        let _ = std::io::stdout().flush();
        let p2 = read_password();
        println!();
        if p.len() < 8 {
            println!("  password must be at least 8 characters");
        } else if p != p2 {
            println!("  passwords do not match");
        } else {
            return Ok(p);
        }
    }
}
