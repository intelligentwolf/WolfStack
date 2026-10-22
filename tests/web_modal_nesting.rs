// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Build-time enforcement: no modal in `web/index.html` sits inside another
//! modal, no `<div>` is still open when `</body>` arrives, and no `</div>`
//! closes nothing.
//!
//! WHY THIS FILE EXISTS
//!
//! `d45d141f` (the web console) replaced the closing `</div>` of
//! `#add-server-modal` with the console markup. The browser closed the overlay
//! implicitly at `</body>`, so every modal written after it became its child.
//! `.modal-overlay` is `opacity: 0; pointer-events: none` until it is opened,
//! so its children were never visible. "Enable 2FA" opened its dialog
//! invisibly (Mancolt, 2026-10-22), and the login welcome, the support nag
//! and the Getting Started course drawer never once showed. The shared
//! confirm dialog and the Apps drawer survived only because their open
//! functions move them to `<body>` first. Nothing failed to compile
//! and nothing logged an error. This test makes the next such slip fail the build.

use std::fs;

/// Elements that never get a matching end tag (HTML spec, void elements).
const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "source", "track", "wbr",
];

/// Elements whose content is raw text. A `<div>` inside a template literal
/// in an inline script is not markup.
const RAW_TEXT: &[&str] = &["script", "style", "textarea"];

struct Open {
    name: String,
    id: String,
    line: usize,
    is_modal_root: bool,
}

/// Value of attribute `name` in the attribute text of one start tag.
fn attr(attrs: &str, name: &str) -> Option<String> {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') { i += 1; }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' && bytes[i] != b'/' { i += 1; }
        let key = &attrs[start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let vs = i;
                while i < bytes.len() && bytes[i] != q { i += 1; }
                value = attrs[vs..i].to_string();
                i += 1;
            } else {
                let vs = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() { i += 1; }
                value = attrs[vs..i].to_string();
            }
        }
        if key.eq_ignore_ascii_case(name) { return Some(value); }
        if start == i { i += 1; }
    }
    None
}

/// A surface that floats over the page: a `.modal-overlay`, a `.welcome-modal`,
/// an inline-styled overlay whose id ends in `-modal` (e.g. `#totp-setup-modal`),
/// a slide-out `-drawer`, or anything declared `role="dialog"`.
fn is_modal_root(id: &str, class: &str, role: &str) -> bool {
    id.ends_with("-modal")
        || id.ends_with("-drawer")
        || role == "dialog"
        || class.split_whitespace().any(|c| c == "modal-overlay" || c == "welcome-modal")
}

#[test]
fn no_modal_is_nested_inside_another_modal() {
    let html = fs::read_to_string("web/index.html").expect("read web/index.html");
    let bytes = html.as_bytes();
    let line_at = |pos: usize| html[..pos].bytes().filter(|&b| b == b'\n').count() + 1;

    let mut stack: Vec<Open> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut body_closed = false;
    let mut modal_roots = 0usize;
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        let lt = i + off;
        if html[lt..].starts_with("<!--") {
            i = html[lt..].find("-->").map(|e| lt + e + 3).unwrap_or(html.len());
            continue;
        }
        if html[lt..].starts_with("<!") {
            i = html[lt..].find('>').map(|e| lt + e + 1).unwrap_or(html.len());
            continue;
        }
        let closing = bytes.get(lt + 1) == Some(&b'/');
        let name_start = lt + 1 + closing as usize;
        let mut name_end = name_start;
        while name_end < bytes.len() && (bytes[name_end].is_ascii_alphanumeric() || bytes[name_end] == b'-') {
            name_end += 1;
        }
        if name_end == name_start {
            i = lt + 1;
            continue;
        }
        let name = html[name_start..name_end].to_ascii_lowercase();
        // End of the tag: first `>` outside a quoted attribute value, since
        // inline handlers (onclick="a > b") may contain `>`.
        let mut j = name_end;
        let mut quote: Option<u8> = None;
        while j < bytes.len() {
            match (quote, bytes[j]) {
                (None, b'>') => break,
                (None, q @ (b'"' | b'\'')) => quote = Some(q),
                (Some(q), c) if c == q => quote = None,
                _ => {}
            }
            j += 1;
        }
        let attrs = &html[name_end..j];
        let tag_end = (j + 1).min(html.len());

        if closing {
            if name == "body" {
                body_closed = true;
                for open in stack.iter().filter(|o| o.name == "div") {
                    failures.push(format!(
                        "<div id=\"{}\"> opened on line {} is still open at </body> (line {})",
                        open.id, open.line, line_at(lt)
                    ));
                }
            }
            // Pop to the matching open element. The browser ignores an
            // unmatched end tag, but a stray </div> means the nesting is not
            // what the author thinks: the div it was meant to close was
            // closed earlier, or one more is still open.
            if let Some(pos) = stack.iter().rposition(|o| o.name == name) {
                stack.truncate(pos);
            } else if name == "div" {
                failures.push(format!("stray </div> on line {} closes nothing", line_at(lt)));
            }
            i = tag_end;
            continue;
        }

        let self_closing = attrs.trim_end().ends_with('/');
        let id = attr(attrs, "id").unwrap_or_default();
        let class = attr(attrs, "class").unwrap_or_default();
        let role = attr(attrs, "role").unwrap_or_default();
        let modal_root = is_modal_root(&id, &class, &role);
        modal_roots += modal_root as usize;
        if modal_root
            && let Some(outer) = stack.iter().rev().find(|o| o.is_modal_root)
        {
            failures.push(format!(
                "modal #{} (line {}) is inside modal #{} (line {}). A closed overlay is \
                 opacity:0, so this dialog can never be seen",
                id, line_at(lt), outer.id, outer.line
            ));
        }

        if RAW_TEXT.contains(&name.as_str()) {
            let close = format!("</{}", name);
            i = html[tag_end..].to_ascii_lowercase().find(&close)
                .map(|e| tag_end + e)
                .unwrap_or(html.len());
            continue;
        }
        if !VOID.contains(&name.as_str()) && !self_closing {
            stack.push(Open { name, id, line: line_at(lt), is_modal_root: modal_root });
        }
        i = tag_end;
    }

    // Sanity: a scanner that lost its place would pass vacuously.
    assert!(body_closed, "never reached </body>; the scanner lost its place");
    assert!(modal_roots >= 20, "found only {modal_roots} modals; the scanner lost its place");
    assert!(failures.is_empty(), "web/index.html modal nesting is broken:\n  {}", failures.join("\n  "));
}
