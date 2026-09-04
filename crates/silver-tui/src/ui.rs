//! Rendering. Pure function of [`App`] state, except that it records the
//! message pane's scroll range so key handling can clamp to it.

use chrono::{Local, NaiveDate, TimeZone};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use silver_client::Direction;
use silver_protocol::UserId;
use silver_protocol::envelope::ReceiptKind;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{App, Connection, Level, Pane, View, ViewRow};

/// Rows the compose box may grow to before it scrolls.
const INPUT_MAX_ROWS: u16 = 6;

/// One row of the message pane before it is drawn: the styled line and
/// which entry of the pane's list it came from.
type Row = (Line<'static>, Option<usize>);

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let [sidebar, chat] =
        Layout::horizontal([Constraint::Length(app.sidebar_width), Constraint::Min(20)])
            .areas(main);
    let input_rows = (app.input.split('\n').count() as u16).clamp(1, INPUT_MAX_ROWS);
    let [messages, input] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(input_rows + 2)]).areas(chat);

    draw_sidebar(frame, app, sidebar);
    draw_messages(frame, app, messages);
    draw_input(frame, app, input);
    draw_status(frame, app, status);
    app.view.sidebar = sidebar;
    app.view.input = input;
    app.view.status = status;
    if app.help_open {
        draw_help(frame, app);
    }
}

/// The help overlay: every command and key, over the middle of the screen,
/// scrolling when the terminal is too short for all of it.
fn draw_help(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).clamp(20, 108).min(area.width);
    let inner_width = width.saturating_sub(2) as usize;
    let heading =
        |t: &str| Line::styled(t.to_owned(), Style::default().add_modifier(Modifier::BOLD));
    let mut text: Vec<Line> = vec![heading("Commands")];
    for c in crate::commands::COMMANDS {
        let head = if c.args.is_empty() {
            format!("/{}", c.name)
        } else {
            format!("/{} {}", c.name, c.args)
        };
        // The description wraps under itself, not under the command.
        text.extend(wrap_message(
            vec![Span::styled(format!("  {head:<28} "), Style::default())],
            c.help,
            dim(),
            inner_width,
        ));
    }
    text.push(Line::from(""));
    text.push(heading("Keys"));
    for k in crate::commands::KEY_HELP {
        text.extend(wrap_message(
            vec![Span::raw("  ")],
            k,
            Style::default(),
            inner_width,
        ));
    }
    let total = text.len();
    let height = (total as u16 + 2)
        .clamp(3, area.height.saturating_sub(2).max(3))
        .min(area.height);
    let visible = height.saturating_sub(2) as usize;
    app.help_scroll = app.help_scroll.min(total.saturating_sub(visible));
    let rect = Rect::new(
        area.width.saturating_sub(width) / 2,
        area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, rect);
    let mut block = Block::bordered().title(" Help · any other key closes ");
    let below = total.saturating_sub(app.help_scroll + visible);
    if below > 0 {
        block = block.title_bottom(Line::styled(
            format!(" {} {below} more (PgDn) ", app.glyphs.more_below),
            dim(),
        ));
    }
    let shown: Vec<Line> = text
        .into_iter()
        .skip(app.help_scroll)
        .take(visible)
        .collect();
    frame.render_widget(Paragraph::new(shown).block(block), rect);
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
        let unread = app
            .unread
            .get(&contact.user_id)
            .map(|ids| ids.len())
            .filter(|n| *n > 0);
        let label = if contact.verified {
            format!("{} {}", app.glyphs.verified, contact.display_name())
        } else {
            contact.display_name()
        };
        lines.push(row(label, unread, app.selected == i + 1));
    }
    if !app.requests.is_empty() {
        lines.push(row(
            "Requests".into(),
            Some(app.held_message_count()),
            app.requests_pane_selected(),
        ));
    }
    if app.contacts.is_empty() && app.requests.is_empty() {
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

    let (title, rows, pane) = match app.selected_contact() {
        None if app.requests_pane_selected() => (
            " Contact requests ".to_owned(),
            request_rows(app, width),
            Pane::Requests,
        ),
        None => (" System ".to_owned(), system_rows(app, width), Pane::System),
        Some(contact) => (
            format!(
                " {}{} · {}{} ",
                if contact.verified {
                    format!("{} ", app.glyphs.verified)
                } else {
                    String::new()
                },
                contact.display_name(),
                contact.user_id,
                app.encryption_label(contact)
                    .map(|l| format!(" · {l}"))
                    .unwrap_or_default()
            ),
            thread_rows(app, &contact.user_id, width),
            Pane::Thread(contact.user_id),
        ),
    };

    let total = rows.len();
    app.max_scroll = total.saturating_sub(height);
    app.scroll = app.scroll.min(app.max_scroll);
    let end = total.saturating_sub(app.scroll);
    let start = end.saturating_sub(height);
    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    // A pane drawn at another width lays its rows out differently, so a
    // selection made before no longer names the same text.
    if app.view.messages.width != inner.width || app.view.pane != pane {
        app.selection = None;
    }
    let (visible, recorded): (Vec<Line>, Vec<ViewRow>) = rows
        .into_iter()
        .map(|(line, source)| {
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            (line, ViewRow { text, source })
        })
        .unzip();
    let visible: Vec<Line> = visible.into_iter().skip(start).take(end - start).collect();

    let mut block = Block::bordered().title(truncate(&title, width));
    if app.scroll > 0 {
        block = block.title_bottom(Line::styled(
            format!(" {} {} more ", app.glyphs.more_below, app.scroll),
            dim(),
        ));
    }
    frame.render_widget(Paragraph::new(visible).block(block), area);
    if total > height && height > 0 {
        // On the right border, between the corners; clicks and drags on
        // it scroll (see App::on_scrollbar).
        let mut state = ScrollbarState::new(total.saturating_sub(height)).position(start);
        let track = Rect::new(
            area.x,
            area.y + 1,
            area.width,
            area.height.saturating_sub(2),
        );
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            track,
            &mut state,
        );
    }
    app.view = View {
        pane,
        messages: inner,
        rows: recorded,
        start,
        sidebar: app.view.sidebar,
        input: app.view.input,
        status: app.view.status,
    };
    highlight_selection(frame, app, inner, start, end);
}

/// Draw the selection over the rows just rendered, by reversing the cells
/// it covers.
fn highlight_selection(frame: &mut Frame, app: &App, inner: Rect, start: usize, end: usize) {
    let Some(selection) = app.selection else {
        return;
    };
    let ((r0, c0), (r1, c1)) = selection.bounds();
    let reversed = Style::default().add_modifier(Modifier::REVERSED);
    let buf = frame.buffer_mut();
    for row in r0.max(start)..=r1.min(end.saturating_sub(1)) {
        if row < start {
            continue;
        }
        let y = inner.y + (row - start) as u16;
        let (from, to) = if selection.rows_only {
            (0, inner.width as usize)
        } else {
            let from = if row == r0 { c0 } else { 0 };
            let to = if row == r1 {
                c1.saturating_add(1).min(inner.width as usize)
            } else {
                inner.width as usize
            };
            (from, to)
        };
        for col in from..to {
            if let Some(cell) = buf.cell_mut((inner.x + col as u16, y)) {
                cell.set_style(reversed);
            }
        }
    }
}

fn system_rows(app: &App, width: usize) -> Vec<Row> {
    let mut rows = Vec::new();
    for (i, line) in app.system.iter().enumerate() {
        let style = match line.level {
            Level::Info => Style::default(),
            Level::Warn => Style::default().fg(Color::Yellow),
            Level::Code => {
                // Dark modules on a light ground whatever the theme, so a
                // phone camera reads it.
                rows.push((
                    Line::styled(
                        truncate(&line.text, width),
                        Style::default().fg(Color::Black).bg(Color::White),
                    ),
                    Some(i),
                ));
                continue;
            }
        };
        let prefix = vec![Span::styled(
            format!("{} ", clock(line.timestamp_ms)),
            dim(),
        )];
        rows.extend(
            wrap_message(prefix, &line.text, style, width)
                .into_iter()
                .map(|l| (l, Some(i))),
        );
    }
    rows
}

fn request_rows(app: &App, width: usize) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    rows.extend(wrap_message(
        vec![],
        "People who wrote to you but are not contacts yet. /accept <n> starts a chat with them; /block <n> drops their messages from now on.",
        dim(),
        width,
    ).into_iter().map(|l| (l, None)));
    rows.push((Line::from(""), None));
    for (i, request) in app.requests.iter().enumerate() {
        rows.push((
            Line::from(vec![
                Span::styled(
                    format!("{}. {}…", i + 1, request.from.short()),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {}", request.from), dim()),
            ]),
            None,
        ));
        let shown = request.messages.len().min(3);
        for held in &request.messages[request.messages.len() - shown..] {
            let prefix = vec![Span::styled(
                format!("   {} ", clock(held.timestamp_ms)),
                dim(),
            )];
            rows.extend(
                wrap_message(prefix, &held.text, Style::default(), width)
                    .into_iter()
                    .map(|l| (l, None)),
            );
        }
        if request.messages.len() > shown {
            rows.push((
                Line::styled(
                    format!("   … and {} earlier", request.messages.len() - shown),
                    dim(),
                ),
                None,
            ));
        }
        rows.push((Line::from(""), None));
    }
    rows
}

fn thread_rows(app: &App, peer: &UserId, width: usize) -> Vec<Row> {
    let Some(lines) = app.threads.get(peer) else {
        return Vec::new();
    };
    let peer_name = app
        .contacts
        .iter()
        .find(|c| c.user_id == *peer)
        .map(|c| c.display_name())
        .unwrap_or_default();
    let mut rows: Vec<Row> = Vec::new();
    let mut last_day: Option<NaiveDate> = None;
    for (i, line) in lines.iter().enumerate() {
        // A separator whenever the calendar day changes.
        let day = Local
            .timestamp_millis_opt(line.timestamp_ms as i64)
            .single()
            .map(|t| t.date_naive());
        if day != last_day {
            if let Some(day) = day {
                rows.push((
                    separator(&day.format(" %A %-d %B %Y ").to_string(), width),
                    None,
                ));
            }
            last_day = day;
        }
        let (name, name_style) = match line.direction {
            Direction::Sent => ("you".to_owned(), Style::default().fg(Color::Green)),
            Direction::Received => (peer_name.clone(), Style::default().fg(Color::Cyan)),
        };
        // ⋯ waiting for the relay, ✓ accepted by the relay, ✓✓ delivered to
        // their device, ✓✓ in colour read, ✗ refused for good (or their
        // ASCII stand-ins).
        let g = app.glyphs;
        let (mark, mark_style) = match line.direction {
            Direction::Sent if line.failed => (g.failed, Style::default().fg(Color::Red)),
            Direction::Sent if !line.delivered => (g.pending, dim()),
            Direction::Sent => match line.receipt {
                Some(ReceiptKind::Read) => (
                    g.delivered,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Some(ReceiptKind::Delivered) => (g.delivered, dim()),
                None => (g.accepted, dim()),
            },
            Direction::Received => ("", Style::default()),
        };
        let mark = if mark.is_empty() {
            String::new()
        } else {
            format!(" {mark}")
        };
        let prefix = vec![
            Span::styled(format!("{} ", clock(line.timestamp_ms)), dim()),
            Span::styled(name, name_style.add_modifier(Modifier::BOLD)),
            Span::styled(mark, mark_style),
            Span::raw(": "),
        ];
        rows.extend(
            wrap_message(prefix, &line.text, Style::default(), width)
                .into_iter()
                .map(|l| (l, Some(i))),
        );
    }
    rows
}

/// The text of `text` between display columns `from` and `to` (inclusive),
/// as a terminal would select it.
pub fn slice_columns(text: &str, from: usize, to: usize) -> String {
    let mut out = String::new();
    let mut col = 0;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(0);
        if col > to {
            break;
        }
        if col >= from {
            out.push(ch);
        }
        col += w;
    }
    out
}

/// The word (run of non-blank characters) under display column `col`, as
/// its first and last column.
pub fn word_at(text: &str, col: usize) -> Option<(usize, usize)> {
    let mut start = None;
    let mut cursor = 0;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(0).max(1);
        if ch.is_whitespace() {
            if let Some(s) = start.take()
                && col < cursor
            {
                return Some((s, cursor - 1));
            }
        } else if start.is_none() {
            start = Some(cursor);
        }
        cursor += w;
    }
    match start {
        Some(s) if col >= s && col < cursor => Some((s, cursor - 1)),
        _ => None,
    }
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let inner_height = area.height.saturating_sub(2) as usize;
    let title = if app.input.starts_with('/') {
        " Command "
    } else if app.input.contains('\n') {
        " Message (Alt-Enter for a new line, Enter sends) "
    } else {
        " Message "
    };

    // Keep the cursor visible: scroll the box vertically to its line and
    // that line horizontally to its column.
    let lines: Vec<&str> = app.input.split('\n').collect();
    let (cursor_line, cursor_chars) = app.cursor_line_col();
    let top = (cursor_line + 1).saturating_sub(inner_height.max(1));
    let cursor_col: usize = lines[cursor_line]
        .chars()
        .take(cursor_chars)
        .map(|c| c.width().unwrap_or(0))
        .sum();
    let offset = cursor_col.saturating_sub(inner_width.saturating_sub(1));
    let shown: Vec<Line> = lines
        .iter()
        .enumerate()
        .skip(top)
        .take(inner_height.max(1))
        .map(|(i, text)| {
            if i == cursor_line {
                Line::from(skip_width(text, offset))
            } else {
                Line::from((*text).to_owned())
            }
        })
        .collect();

    frame.render_widget(
        Paragraph::new(shown).block(Block::bordered().title(title)),
        area,
    );
    let x = area.x + 1 + (cursor_col - offset).min(inner_width.saturating_sub(1)) as u16;
    let y = area.y + 1 + (cursor_line - top) as u16;
    frame.set_cursor_position(Position::new(x, y));
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let g = app.glyphs;
    let (dot, label, color) = match app.connection {
        Connection::Connecting => (g.connecting, "connecting", Color::Yellow),
        Connection::Connected => (g.connected, "connected", Color::Green),
        Connection::Disconnected => (g.disconnected, "disconnected", Color::Red),
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
            spans.push(Span::styled(format!("  {}", app.status_hint()), dim()));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// --- text helpers ----------------------------------------------------------

pub fn clock(timestamp_ms: u64) -> String {
    Local
        .timestamp_millis_opt(timestamp_ms as i64)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".into())
}

/// Date and time, for lines shown outside their conversation.
pub fn stamp(timestamp_ms: u64) -> String {
    Local
        .timestamp_millis_opt(timestamp_ms as i64)
        .single()
        .map(|t| t.format("%-d %b %H:%M").to_string())
        .unwrap_or_else(|| "--:--".into())
}

/// A dim rule with `text` in the middle, `width` columns wide.
fn separator(text: &str, width: usize) -> Line<'static> {
    let text_width = text.width().min(width);
    let left = width.saturating_sub(text_width) / 2;
    let right = width.saturating_sub(text_width + left);
    Line::styled(
        format!(
            "{}{}{}",
            "─".repeat(left),
            truncate(text, width),
            "─".repeat(right)
        ),
        dim(),
    )
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

    #[test]
    fn selection_helpers_work_in_columns() {
        assert_eq!(slice_columns("hello world", 6, 10), "world");
        assert_eq!(slice_columns("hello world", 0, 4), "hello");
        assert_eq!(slice_columns("hello", 3, 99), "lo");
        // A wide character occupies two columns.
        assert_eq!(slice_columns("a日b", 1, 2), "日");
        assert_eq!(word_at("hello world", 7), Some((6, 10)));
        assert_eq!(word_at("hello world", 0), Some((0, 4)));
        assert_eq!(word_at("hello world", 5), None);
        assert_eq!(word_at("hello", 9), None);
        assert_eq!(word_at("  x", 2), Some((2, 2)));
    }
}
