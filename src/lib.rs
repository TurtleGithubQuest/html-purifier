//! # HTML Purifier
//!
//! HTML Purifier is a standard HTML filter library.
//!
//! > HTML Purifier will not only remove all malicious code (better known as XSS) with a thoroughly audited, secure yet permissive whitelist, it will also make sure your documents are standards compliant, something only achievable with a comprehensive knowledge of W3C's specifications. [HTML Purifier](http://htmlpurifier.org)
//!
//! ## Example
//!
//! ```
//! use html_purifier::{purifier, Settings};
//!
//! let settings = Settings {
//!     ..Settings::default()
//! };
//! let input = r#"<a href="/test" style="color: black;"><img src="/logo.png" onerror="javascript:;"/>Rust</a>"#;
//! let output = purifier(input, settings);
//! ```
//!
//! Input HTML
//!
//! ```notrust
//! <a href="/test" style="color: black;"
//!   ><img src="/logo.png" onerror="javascript:;" />Rust</a
//! >
//! ```
//!
//! Output HTML
//!
//! ```notrust
//! <a href="/test"><img src="/logo.png" />Rust</a>
//! ```

use lol_html::html_content::{Comment, Element};
use lol_html::{comments, element, rewrite_str, RewriteStrSettings};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllowedElement<'a> {
    pub name: &'a str,
    pub attributes: Vec<&'a str>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settings<'a> {
    #[serde(borrow)]
    pub allowed: Vec<AllowedElement<'a>>,
    pub remove_comments: bool,
}

impl<'a> Default for Settings<'a> {
    #[inline]
    fn default() -> Self {
        Settings {
            allowed: vec![
                AllowedElement {
                    name: "div",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "b",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "strong",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "i",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "em",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "u",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "a",
                    attributes: vec!["href", "title"],
                },
                AllowedElement {
                    name: "ul",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "ol",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "li",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "p",
                    attributes: vec!["style"],
                },
                AllowedElement {
                    name: "br",
                    attributes: vec![],
                },
                AllowedElement {
                    name: "span",
                    attributes: vec!["style"],
                },
                AllowedElement {
                    name: "img",
                    attributes: vec![
                        "width",
                        "height",
                        "alt",
                        "src",
                    ],
                },
            ],
            remove_comments: true,
        }
    }
}

/// HTML Purifier
///
/// # Example
///
/// ```
/// use html_purifier::{purifier, Settings};
///
/// let settings = Settings {
///     ..Settings::default()
/// };
/// let input = r#"<a href="/test" style="color: black;"><img src="/logo.png" onerror="javascript:;"/>Rust</a>"#;
/// let output = purifier(input, settings);
/// ```
pub fn purifier(input: &str, settings: Settings) -> String {
    let element_handler = |el: &mut Element| {
        if let Some(find) = settings.allowed.iter().find(|e| e.name.eq(&el.tag_name())) {
            let remove_attributes: Vec<String> = el
                .attributes()
                .iter()
                .filter(|attr| !find.attributes.contains(&&*attr.name()))
                .map(|attr| attr.name())
                .collect();
            for attr in remove_attributes {
                el.remove_attribute(&*attr);
            }
        } else {
            el.remove_and_keep_content();
        }
        Ok(())
    };

    let comment_handler = |c: &mut Comment| {
        if settings.remove_comments {
            c.remove();
        }
        Ok(())
    };

    let output = rewrite_str(
        input,
        RewriteStrSettings {
            element_content_handlers: vec![
                element!("*", element_handler),
                comments!("*", comment_handler),
            ],
            ..RewriteStrSettings::default()
        },
    )
    .unwrap();

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_purifier() {
        let settings = Settings {
            ..Settings::default()
        };
        let input = r#"<div style="display: block;"><span style="color: black;"><a href="/test" onclick="javascript:;"><img src="/logo.png" onerror="javascript:;"/>Rust</a></span></div>"#;
        let output = purifier(input, settings);
        assert_eq!(
            output,
            r#"<div><span style="color: black;"><a href="/test"><img src="/logo.png" />Rust</a></span></div>"#
        );
    }
    #[test]
    fn test_purifier_remove_comments() {
        let settings = Settings {
            ..Settings::default()
        };
        let input = r#"<div style="display: block;"><!--Comment 1--><span style="color: black;"><a href="/test" onclick="javascript:;"><img src="/logo.png" onerror="javascript:;"/>Rust</a></span></div>"#;
        let output = purifier(input, settings);
        assert_eq!(
            output,
            r#"<div><span style="color: black;"><a href="/test"><img src="/logo.png" />Rust</a></span></div>"#
        );
    }
    #[test]
    fn test_purifier_show_comments() {
        let settings = Settings {
            remove_comments: false,
            ..Settings::default()
        };
        let input = r#"<div style="display: block;"><span style="color: black;"><!--Comment 1--><a href="/test" onclick="javascript:;"><img src="/logo.png" onerror="javascript:;"/>Rust</a></span></div>"#;
        let output = purifier(input, settings);
        assert_eq!(
            output,
            r#"<div><span style="color: black;"><!--Comment 1--><a href="/test"><img src="/logo.png" />Rust</a></span></div>"#
        );
    }
}
