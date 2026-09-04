//! Rendering. Pure function of [`App`] state, except that it records the
//! message pane's scroll range so key handling can clamp to it.

use chrono::{Local, TimeZone};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use silver_client::Direction;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{App, Connection, Level};

const SIDEBAR_WIDTH: u16 = 26;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let [sidebar, chat] =
        Layout::horizontal([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(20)]).areas(main);
    let [messages, input] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).areas(chat);

    draw_sidebar(frame, app, sidebar);
    draw_messages(frame, app, messages);
    draw_input(frame, app, input);
    draw_status(frame, app, status);
}

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn selected_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn draw_sidebar(frame: &mut Frame, app: &App, area: Rect) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let mut lines = Vec::with_capacity(app.contacts.len() + 2);

    let row = |label: String, badge: Option<usize>, selected: bool| -> Line<'static> {
        let badge = badge.map(|n| format!(" {n} ")).unwrap_or_default();
        let room = inner_width.saturating_sub(badge.width() + 1);
        let label = truncate(&label, room);
        let pad = inner_width.saturating_sub(label.width() + badge.width());
        let style = if selected {
            selected_style()
        } else {
            Style::default()
        };
        let badge_style = if selected {
            style
        } else {
            Style::default().fg(Color::Black).bg(Color::Yellow)
        };
        Line::from(vec![
            Span::styled(
                format!(" {label}{}", " ".repeat(pad.saturating_sub(1))),
                style,
            ),
            Span::styled(badge, badge_style),
        ])
    };

    lines.push(row("System".into(), None, app.selected == 0));
    for (i, contact) in app.contacts.iter().enumerate() {
        let unread = app.unread.get(&contact.user_id).copied().filter(|n| *n > 0);
        lines.push(row(contact.display_name(), unread, app.selected == i + 1));
    }
    if app.contacts.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(" no contacts yet", dim()));
        lines.push(Line::styled(" /add <user-id>", dim()));
    }

    let block = Block::bordered().title(" Chats ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_messages(frame: &mut Frame, app: &mut App, area: Rect) {
    let width = area.width.saturating_sub(2) as usize;
    let height = area.height.saturating_sub(2) as usize;

    let (title, rows) = match app.selected_contact() {
        None => (" System ".to_owned(), system_rows(app, width)),
        Some(contact) => (
            format!(" {} · {} ", contact.display_name(), contact.user_id),
            thread_rows(app, &contact.user_id, width),
        ),
    };

    let total = rows.len();
    app.max_scroll = total.saturating_sub(height);
    app.scroll = app.scroll.min(app.max_scroll);
    let end = total.saturating_sub(app.scroll);
    let start = end.saturating_sub(height);
    let visible: Vec<Line> = rows.into_iter().skip(start).take(end - start).collect();

    let mut block = Block::bordered().title(truncate(&title, width));
    if app.scroll > 0 {
        block = block.title_bottom(Line::styled(format!(" ↓ {} more ", app.scroll), dim()));
    }
    frame.render_widget(Paragraph::new(visible).block(block), area);
}

fn system_rows(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut rows = Vec::new();
    for line in &app.system {
        let style = match line.level {
            Level::Info => Style::default(),
            Level::Warn => Style::default().fg(Color::Yellow),
        };
        let prefix = vec![Span::styled(
            format!("{} ", clock(line.timestamp_ms)),
            dim(),
        )];
        rows.extend(wrap_message(prefix, &line.text, style, width));
    }
    rows
}

fn thread_rows(app: &App, peer: &silver_protocol::UserId, width: usize) -> Vec<Line<'static>> {
    let Some(lines) = app.threads.get(peer) else {
        return Vec::new();
    };
    let peer_name = app
        .contacts
        .iter()
        .find(|c| c.user_id == *peer)
        .map(|c| c.display_name())
        .unwrap_or_default();
    let mut rows = Vec::new();
    for line in lines {
        let (name, name_style) = match line.direction {
            Direction::Sent => ("you".to_owned(), Style::default().fg(Color::Green)),
            Direction::Received => (peer_name.clone(), Style::default().fg(Color::Cyan)),
        };
        let mark = match (line.direction, line.delivered, line.failed) {
            (Direction::Sent, _, true) => " ✗",
            (Direction::Sent, false, false) => " ⋯",
            _ => "",
        };
        let prefix = vec![
            Span::styled(format!("{} ", clock(line.timestamp_ms)), dim()),
            Span::styled(
                format!("{name}{mark}"),
                name_style.add_modifier(Modifier::BOLD),
            ),
            Span::raw(": "),
        ];
        rows.extend(wrap_message(prefix, &line.text, Style::default(), width));
    }
    rows
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let title = if app.input.starts_with('/') {
        " Command "
    } else {
        " Message "
    };

    // Keep the cursor visible by scrolling the input horizontally.
    let cursor_col: usize = app
        .input
        .chars()
        .take(app.cursor)
        .map(|c| c.width().unwrap_or(0))
        .sum();
    let offset = cursor_col.saturating_sub(inner_width.saturating_sub(1));
    let shown: String = skip_width(&app.input, offset);

    frame.render_widget(
        Paragraph::new(shown).block(Block::bordered().title(title)),
        area,
    );
    let x = area.x + 1 + (cursor_col - offset).min(inner_width.saturating_sub(1)) as u16;
    frame.set_cursor_position(Position::new(x, area.y + 1));
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let (dot, label, color) = match app.connection {
        Connection::Connecting => ("◌", "connecting", Color::Yellow),
        Connection::Connected => ("●", "connected", Color::Green),
        Connection::Disconnected => ("○", "disconnected", Color::Red),
    };
    let mut spans = vec![
        Span::styled(format!(" {dot} {label} "), Style::default().fg(color)),
        Span::styled(app.relay_url.clone(), dim()),
    ];
    let pending = app.pending_count();
    if pending > 0 {
        spans.push(Span::styled(
            format!("  {pending} queued"),
            Style::default().fg(Color::Yellow),
        ));
    }
    match &app.toast {
        Some((text, _)) => {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                text.clone(),
                Style::default().fg(Color::Yellow),
            ));
        }
        None => {
            spans.push(Span::styled(format!("  you: {}", app.me), dim()));
            spans.push(Span::styled("  /help", dim()));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// --- text helpers ----------------------------------------------------------

fn clock(timestamp_ms: u64) -> String {
    Local
        .timestamp_millis_opt(timestamp_ms as i64)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".into())
}

/// Lay out `prefix` followed by word-wrapped `text`; continuation rows are
/// indented to the prefix width.
fn wrap_message(
    prefix: Vec<Span<'static>>,
    text: &str,
    style: Style,
    width: usize,
) -> Vec<Line<'static>> {
    let width = width.max(8);
    let prefix_width: usize = prefix.iter().map(|s| s.content.width()).sum();
    let indent = prefix_width.min(width / 2);
    let mut rows = Vec::new();
    let mut first = true;
    for chunk in wrap_text(text, width.saturating_sub(indent).max(1)) {
        if first {
            let mut spans = prefix.clone();
            spans.push(Span::styled(chunk, style));
            rows.push(Line::from(spans));
            first = false;
        } else {
            rows.push(Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(chunk, style),
            ]));
        }
    }
    if rows.is_empty() {
        rows.push(Line::from(prefix));
    }
    rows
}

/// Greedy word wrap on display width; over-long words are split hard.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut current = String::new();
        let mut current_width = 0;
        for word in para.split(' ') {
            let word_width = word.width();
            if word_width > width {
                if !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                }
                let mut piece = String::new();
                let mut piece_width = 0;
                for ch in word.chars() {
                    let w = ch.width().unwrap_or(0);
                    if piece_width + w > width && !piece.is_empty() {
                        lines.push(std::mem::take(&mut piece));
                        piece_width = 0;
                    }
                    piece.push(ch);
                    piece_width += w;
                }
                current = piece;
                current_width = piece_width;
            } else if current.is_empty() {
                current.push_str(word);
                current_width = word_width;
            } else if current_width + 1 + word_width <= width {
                current.push(' ');
                current.push_str(word);
                current_width += 1 + word_width;
            } else {
                lines.push(std::mem::replace(&mut current, word.to_owned()));
                current_width = word_width;
            }
        }
        lines.push(current);
    }
    lines
}

/// Cut `text` to at most `width` columns, with an ellipsis if shortened.
fn truncate(text: &str, width: usize) -> String {
    if text.width() <= width {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w + 1 > width {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

/// Drop leading characters until `columns` display columns have been skipped.
fn skip_width(text: &str, columns: usize) -> String {
    let mut skipped = 0;
    text.chars()
        .skip_while(|c| {
            if skipped >= columns {
                return false;
            }
            skipped += c.width().unwrap_or(0);
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_on_words_and_splits_long_ones() {
        assert_eq!(
            wrap_text("the quick brown fox", 9),
            ["the quick", "brown fox"]
        );
        assert_eq!(wrap_text("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap_text("a\nb", 10), ["a", "b"]);
        assert_eq!(wrap_text("", 10), [""]);
    }

    #[test]
    fn truncates_with_ellipsis() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
    }
}
