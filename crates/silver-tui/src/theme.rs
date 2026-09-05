//! Colours. Four palettes: dark (the default, for the usual dark
//! terminal), light for a light background, mono for terminals without
//! colour or people who set `NO_COLOR`, which leans on bold, dim and
//! reverse video instead, and contrast for low vision: bright bold text
//! on black, nothing dimmed, every pair well above the 7:1 the WCAG asks
//! of small text (`docs/design/accessibility.md`). The QR code is always
//! dark on light, whatever the palette, so a phone can read it.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeName {
    Dark,
    Light,
    Mono,
    Contrast,
}

impl ThemeName {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "dark" | "default" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "mono" | "none" | "plain" | "nocolor" | "no-color" => Some(Self::Mono),
            "contrast" | "high-contrast" | "highcontrast" | "hc" => Some(Self::Contrast),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Mono => "mono",
            Self::Contrast => "contrast",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub name: ThemeName,
    /// The ground everything is drawn on: the terminal's own colours in
    /// most palettes, white on black in `contrast`, which assumes nothing
    /// of the terminal.
    pub text: Style,
    /// Timestamps, hints, rules and other things that should not shout.
    pub dim: Style,
    /// The focused pane's border and other things that should stand out.
    pub accent: Style,
    /// The selected entry of the chat list.
    pub selected: Style,
    /// Unread counts.
    pub badge: Style,
    /// Your own name on sent messages.
    pub you: Style,
    /// A contact's name on their messages.
    pub peer: Style,
    pub warn: Style,
    pub error: Style,
    /// Connected, and other good news.
    pub good: Style,
    /// The read mark.
    pub read: Style,
    pub toast: Style,
    /// QR modules: dark on light in every palette.
    pub code: Style,
}

impl Theme {
    pub fn named(name: ThemeName) -> Self {
        match name {
            ThemeName::Dark => Self::dark(),
            ThemeName::Light => Self::light(),
            ThemeName::Mono => Self::mono(),
            ThemeName::Contrast => Self::contrast(),
        }
    }

    pub fn dark() -> Self {
        Self {
            name: ThemeName::Dark,
            text: Style::default(),
            dim: fg(Color::DarkGray),
            accent: fg(Color::Cyan),
            selected: fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            badge: fg(Color::Black).bg(Color::Yellow),
            you: fg(Color::Green),
            peer: fg(Color::Cyan),
            warn: fg(Color::Yellow),
            error: fg(Color::Red),
            good: fg(Color::Green),
            read: fg(Color::Cyan).add_modifier(Modifier::BOLD),
            toast: fg(Color::Yellow),
            code: fg(Color::Black).bg(Color::White),
        }
    }

    pub fn light() -> Self {
        Self {
            name: ThemeName::Light,
            text: Style::default(),
            dim: fg(Color::DarkGray),
            accent: fg(Color::Blue),
            selected: fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
            badge: fg(Color::White).bg(Color::Red),
            you: fg(Color::Green),
            peer: fg(Color::Blue),
            warn: fg(Color::Magenta),
            error: fg(Color::Red),
            good: fg(Color::Green),
            read: fg(Color::Blue).add_modifier(Modifier::BOLD),
            toast: fg(Color::Magenta),
            code: fg(Color::Black).bg(Color::White),
        }
    }

    pub fn mono() -> Self {
        let plain = Style::default();
        Self {
            name: ThemeName::Mono,
            text: plain,
            dim: plain.add_modifier(Modifier::DIM),
            accent: plain.add_modifier(Modifier::BOLD),
            selected: plain.add_modifier(Modifier::REVERSED | Modifier::BOLD),
            badge: plain.add_modifier(Modifier::REVERSED),
            you: plain.add_modifier(Modifier::BOLD),
            peer: plain.add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            warn: plain.add_modifier(Modifier::BOLD),
            error: plain.add_modifier(Modifier::BOLD | Modifier::REVERSED),
            good: plain,
            read: plain.add_modifier(Modifier::BOLD),
            toast: plain.add_modifier(Modifier::BOLD),
            code: fg(Color::Black).bg(Color::White),
        }
    }

    /// Bright bold text on black, every pair set on both sides so the
    /// terminal's own colours play no part, nothing dimmed. Bright yellow
    /// and bright white on black, and black on bright yellow, are above
    /// 10:1 in the usual palettes; white on red, the weakest pair at about
    /// 5:1, marks errors alone, which are short and bold.
    pub fn contrast() -> Self {
        let base = Style::default().fg(Color::White).bg(Color::Black);
        let bold = base.add_modifier(Modifier::BOLD);
        Self {
            name: ThemeName::Contrast,
            text: base,
            dim: base,
            accent: bold.fg(Color::LightYellow),
            selected: bold.fg(Color::Black).bg(Color::LightYellow),
            badge: bold.fg(Color::Black).bg(Color::LightYellow),
            you: bold.fg(Color::LightYellow),
            peer: bold.fg(Color::LightYellow),
            warn: bold.fg(Color::LightYellow),
            error: bold.fg(Color::White).bg(Color::Red),
            good: bold.fg(Color::LightGreen),
            read: bold.fg(Color::LightCyan),
            toast: bold.fg(Color::White).bg(Color::Blue),
            code: fg(Color::Black).bg(Color::White),
        }
    }

    /// Every style of the palette but the QR code's.
    #[cfg(test)]
    pub fn styles(&self) -> [Style; 12] {
        [
            self.text,
            self.dim,
            self.accent,
            self.selected,
            self.badge,
            self.you,
            self.peer,
            self.warn,
            self.error,
            self.good,
            self.read,
            self.toast,
        ]
    }
}

fn fg(color: Color) -> Style {
    Style::default().fg(color)
}

/// The palette to start with: the command line, else `NO_COLOR`, else the
/// config, else dark.
pub fn choose(flag: Option<&str>, config: &str, no_color: bool) -> ThemeName {
    if let Some(name) = flag.and_then(ThemeName::parse) {
        return name;
    }
    if no_color {
        return ThemeName::Mono;
    }
    ThemeName::parse(config).unwrap_or(ThemeName::Dark)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_palette_is_chosen_in_order() {
        assert_eq!(choose(Some("light"), "dark", true), ThemeName::Light);
        assert_eq!(choose(None, "light", true), ThemeName::Mono);
        assert_eq!(choose(None, "light", false), ThemeName::Light);
        assert_eq!(choose(None, "nonsense", false), ThemeName::Dark);
        assert_eq!(ThemeName::parse("NONE"), Some(ThemeName::Mono));
    }

    #[test]
    fn mono_uses_no_colour_except_for_the_code() {
        let t = Theme::mono();
        for style in t.styles() {
            assert!(style.fg.is_none() && style.bg.is_none());
        }
        assert_eq!(t.code.fg, Some(Color::Black));
    }

    #[test]
    fn contrast_sets_both_sides_of_every_pair_and_dims_nothing() {
        let t = Theme::contrast();
        for style in t.styles() {
            assert!(style.fg.is_some() && style.bg.is_some(), "{style:?}");
            assert!(!style.add_modifier.contains(Modifier::DIM));
        }
        assert_eq!(t.text, t.dim, "nothing is dimmed");
        assert_eq!(ThemeName::parse("high-contrast"), Some(ThemeName::Contrast));
        assert_eq!(Theme::named(ThemeName::Contrast).name.as_str(), "contrast");
    }
}
