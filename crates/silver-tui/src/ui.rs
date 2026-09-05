//! Rendering. Pure function of [`App`] state, except that it records the
//! message pane's scroll range so key handling can clamp to it.

use chrono::{Local, NaiveDate, TimeZone};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use silver_client::Direction;
use silver_protocol::UserId;
use silver_protocol::envelope::ReceiptKind;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{App, ChatLine, Connection, Level, Pane, View, ViewRow};

/// Rows the compose box may grow to before it scrolls.
const INPUT_MAX_ROWS: u16 = 6;

/// One row of the message pane before it is drawn: the styled line and
/// which entry of the pane's list it came from.
type Row = (Line<'static>, Option<usize>);

/// Below this many columns the chat list is folded away and the chat
/// title says which pane this is.
const NARROW_WIDTH: u16 = 70;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    app.narrow = frame.area().width < NARROW_WIDTH;
    let sidebar_width = if app.narrow { 0 } else { app.sidebar_width };
    let [sidebar, chat] =
        Layout::horizontal([Constraint::Length(sidebar_width), Constraint::Min(20)]).areas(main);
    let input_rows = (app.input.split('\n').count() as u16).clamp(1, INPUT_MAX_ROWS);
    let [messages, input] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(input_rows + 2)]).areas(chat);

    if !app.narrow {
        draw_sidebar(frame, app, sidebar);
    }
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
            app.theme.dim,
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
            app.theme.dim,
        ));
    }
    let shown: Vec<Line> = text
        .into_iter()
        .skip(app.help_scroll)
        .take(visible)
        .collect();
    frame.render_widget(Paragraph::new(shown).block(block), rect);
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
            app.theme.selected
        } else {
            Style::default()
        };
        let badge_style = if selected { style } else { app.theme.badge };
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
        let label = if contact.revoked {
            format!("{} (revoked)", contact.display_name())
        } else if contact.verified {
            format!("{} {}", app.glyphs.verified, contact.display_name())
        } else {
            contact.display_name()
        };
        lines.push(row(label, unread, app.selected == i + 1));
    }
    for (i, group) in app.group_list.iter().enumerate() {
        let unread = app
            .group_unread
            .get(group)
            .map(|ids| ids.len())
            .filter(|n| *n > 0);
        let label = match app.group_state_label(group) {
            Some(state) => format!("# {} ({state})", app.group_name(group)),
            None => format!("# {}", app.group_name(group)),
        };
        lines.push(row(
            label,
            unread,
            app.selected == app.contacts.len() + i + 1,
        ));
    }
    if app.has_requests_pane() {
        lines.push(row(
            "Requests".into(),
            Some(app.held_message_count()),
            app.requests_pane_selected(),
        ));
    }
    if app.contacts.is_empty() && app.requests.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(" no contacts yet", app.theme.dim));
        lines.push(Line::styled(" /add <user-id>", app.theme.dim));
    }

    let block = Block::bordered().title(" Chats ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_messages(frame: &mut Frame, app: &mut App, area: Rect) {
    let width = area.width.saturating_sub(2) as usize;
    let height = area.height.saturating_sub(2) as usize;

    let (title, rows, pane) = match (app.selected_group(), app.selected_contact()) {
        (Some(group), _) => (
            app.group_title(&group),
            group_rows(app, &group, width),
            Pane::Group(group),
        ),
        (None, None) if app.requests_pane_selected() => (
            " Requests ".to_owned(),
            request_rows(app, width),
            Pane::Requests,
        ),
        (None, None) => (" System ".to_owned(), system_rows(app, width), Pane::System),
        (None, Some(contact)) => (
            format!(
                " {}{} · {}{}{} ",
                if contact.verified && !contact.revoked {
                    format!("{} ", app.glyphs.verified)
                } else {
                    String::new()
                },
                contact.display_name(),
                contact.user_id,
                if contact.revoked { " · revoked" } else { "" },
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

    // Without the chat list, the title says where in it this pane sits.
    let title = if app.narrow {
        format!("{}{}/{} ", title, app.selected + 1, app.pane_count())
    } else {
        title
    };
    // The pane with a selection has the keyboard's attention; otherwise
    // the compose box does, and its border says so.
    let mut block = Block::bordered().title(truncate(&title, width));
    if app.selection.is_some() {
        block = block.border_style(app.theme.accent);
    }
    if app.scroll > 0 {
        block = block.title_bottom(Line::styled(
            format!(" {} {} more ", app.glyphs.more_below, app.scroll),
            app.theme.dim,
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
            Level::Warn => app.theme.warn,
            Level::Code => {
                // Dark modules on a light ground whatever the theme, so a
                // phone camera reads it.
                rows.push((
                    Line::styled(truncate(&line.text, width), app.theme.code),
                    Some(i),
                ));
                continue;
            }
        };
        let prefix = vec![Span::styled(
            format!("{} ", clock(line.timestamp_ms)),
            app.theme.dim,
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
        "People who wrote to you but are not contacts yet. /accept <n> starts a chat with them; /block <n> drops their messages from now on. Group invitations from strangers wait here too: /accept g<n> joins, /decline g<n> does not.",
        app.theme.dim,
        width,
    ).into_iter().map(|l| (l, None)));
    rows.push((Line::from(""), None));
    for (i, held) in app.invitations().iter().enumerate() {
        rows.push((
            Line::from(vec![
                Span::styled(
                    format!("g{}. {}", i + 1, held.name),
                    app.theme.accent.add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  a group of {}, from {}… ({})",
                        held.members.len(),
                        held.from.short(),
                        held.from
                    ),
                    app.theme.dim,
                ),
            ]),
            None,
        ));
        rows.push((Line::from(""), None));
    }
    for (i, request) in app.requests.iter().enumerate() {
        rows.push((
            Line::from(vec![
                Span::styled(
                    format!("{}. {}…", i + 1, request.from.short()),
                    app.theme.accent.add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {}", request.from), app.theme.dim),
            ]),
            None,
        ));
        let shown = request.messages.len().min(3);
        for held in &request.messages[request.messages.len() - shown..] {
            let prefix = vec![Span::styled(
                format!("   {} ", clock(held.timestamp_ms)),
                app.theme.dim,
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
                    app.theme.dim,
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
    let marker = app
        .new_marker
        .as_ref()
        .filter(|(p, _)| p == peer)
        .map(|(_, id)| id.as_str());
    lines_rows(
        app,
        lines,
        &|_| peer_name.clone(),
        &|_| peer_name.clone(),
        marker,
        width,
    )
}

fn group_rows(app: &App, group: &silver_protocol::group::GroupId, width: usize) -> Vec<Row> {
    let Some(lines) = app.group_threads.get(group) else {
        return Vec::new();
    };
    let marker = app
        .group_new_marker
        .as_ref()
        .filter(|(g, _)| g == group)
        .map(|(_, id)| id.as_str());
    lines_rows(
        app,
        lines,
        &|line: &ChatLine| match line.sender {
            Some(sender) => app.member_name(&sender),
            None => String::new(),
        },
        &|user: &UserId| app.member_name(user),
        marker,
        width,
    )
}

/// The rows of a conversation: date rules, the "new messages" rule, and
/// each line with its clock, name, mark and text, the quote of what it
/// answers above it and the reactions to it below. `name_of` names the
/// writer of a received line (an empty name is a note about the chat);
/// `who` names whoever reacted.
fn lines_rows(
    app: &App,
    lines: &[ChatLine],
    name_of: &dyn Fn(&ChatLine) -> String,
    who: &dyn Fn(&UserId) -> String,
    marker: Option<&str>,
    width: usize,
) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    let mut last_day: Option<NaiveDate> = None;
    let today = Local::now().date_naive();
    let g = app.glyphs;
    for (i, line) in lines.iter().enumerate() {
        // A separator whenever the calendar day changes.
        let day = Local
            .timestamp_millis_opt(line.timestamp_ms as i64)
            .single()
            .map(|t| t.date_naive());
        if day != last_day {
            if let Some(day) = day {
                rows.push((
                    separator(&day_label(day, today), width, app.theme.dim),
                    None,
                ));
            }
            last_day = day;
        }
        // A rule above what arrived while this chat was not open.
        if marker == Some(line.id.as_str()) {
            rows.push((separator(" new messages ", width, app.theme.accent), None));
        }
        let (name, name_style): (String, Style) = match line.direction {
            Direction::Sent => ("you".to_owned(), app.theme.you),
            Direction::Received => (name_of(line), app.theme.peer),
        };
        let stamp = format!("{} ", clock(line.timestamp_ms));
        let indent = " ".repeat(stamp.width().min(width / 2));
        // Deleted for everyone by its author: a placeholder, dim.
        if line.deleted {
            let text = format!("· {name} deleted a message");
            rows.extend(
                wrap_message(
                    vec![Span::styled(stamp, app.theme.dim)],
                    &text,
                    app.theme.dim,
                    width,
                )
                .into_iter()
                .map(|l| (l, Some(i))),
            );
            continue;
        }
        // The message answered, quoted from this side's own copy of it.
        if let Some(target) = &line.reply_to {
            let quote = match lines.iter().find(|l| l.id == *target) {
                Some(t) if t.deleted => "a deleted message".to_owned(),
                Some(t) => {
                    let author = match t.direction {
                        Direction::Sent => "you".to_owned(),
                        Direction::Received => name_of(t),
                    };
                    let first = t.text.lines().next().unwrap_or_default();
                    format!("{author}: {first}")
                }
                None => "a message you do not have".to_owned(),
            };
            let room = width.saturating_sub(indent.width()).max(1);
            rows.push((
                Line::from(vec![
                    Span::raw(indent.clone()),
                    Span::styled(
                        truncate(&format!("{} {quote}", g.reply), room),
                        app.theme.dim,
                    ),
                ]),
                Some(i),
            ));
        }
        // ⋯ waiting for the relay, ✓ accepted by the relay, ✓✓ delivered to
        // their device, ✓✓ in colour read, ✗ refused for good (or their
        // ASCII stand-ins).
        let (mark, mark_style) = match line.direction {
            Direction::Sent if line.failed => (g.failed, app.theme.error),
            Direction::Sent if !line.delivered => (g.pending, app.theme.dim),
            Direction::Sent => match line.receipt {
                Some(ReceiptKind::Read) => (g.delivered, app.theme.read),
                Some(ReceiptKind::Delivered) => (g.delivered, app.theme.dim),
                None => (g.accepted, app.theme.dim),
            },
            Direction::Received => ("", Style::default()),
        };
        let mark = if mark.is_empty() {
            String::new()
        } else {
            format!(" {mark}")
        };
        // A line with a timer carries the hourglass, so what will go is
        // told from what stays.
        let timer = if line.expire_after_s > 0 {
            format!(" {}", g.timer)
        } else {
            String::new()
        };
        let prefix = if name.is_empty() {
            vec![Span::styled(stamp, app.theme.dim)]
        } else {
            vec![
                Span::styled(stamp, app.theme.dim),
                Span::styled(name, name_style.add_modifier(Modifier::BOLD)),
                Span::styled(mark, mark_style),
                Span::styled(timer, app.theme.dim),
                Span::raw(": "),
            ]
        };
        let style = if line.text.starts_with("· ") {
            app.theme.dim
        } else {
            Style::default()
        };
        let text = if line.edited {
            format!("{} (edited)", line.text)
        } else {
            line.text.clone()
        };
        rows.extend(
            wrap_message(prefix, &text, style, width)
                .into_iter()
                .map(|l| (l, Some(i))),
        );
        // The reactions, by reaction, with the names of those who gave it.
        if !line.reactions.is_empty() {
            let mut given: Vec<(&str, Vec<String>)> = Vec::new();
            for reaction in &line.reactions {
                let name = match reaction.from {
                    None => "you".to_owned(),
                    Some(user) => who(&user),
                };
                match given.iter_mut().find(|(e, _)| *e == reaction.emoji) {
                    Some((_, names)) => names.push(name),
                    None => given.push((reaction.emoji.as_str(), vec![name])),
                }
            }
            let text = given
                .iter()
                .map(|(emoji, names)| format!("{emoji} {}", names.join(", ")))
                .collect::<Vec<_>>()
                .join(" · ");
            let room = width.saturating_sub(indent.width()).max(1);
            rows.push((
                Line::from(vec![
                    Span::raw(indent.clone()),
                    Span::styled(truncate(&text, room), app.theme.dim),
                ]),
                Some(i),
            ));
        }
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
        Paragraph::new(shown).block(Block::bordered().title(title).border_style(
            if app.selection.is_none() && !app.help_open {
                app.theme.accent
            } else {
                Style::default()
            },
        )),
        area,
    );
    let x = area.x + 1 + (cursor_col - offset).min(inner_width.saturating_sub(1)) as u16;
    let y = area.y + 1 + (cursor_line - top) as u16;
    frame.set_cursor_position(Position::new(x, y));
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let g = app.glyphs;
    let (dot, label, style) = match app.connection {
        Connection::Connecting => (g.connecting, "connecting", app.theme.warn),
        Connection::Connected => (g.connected, "connected", app.theme.good),
        Connection::Disconnected => (g.disconnected, "disconnected", app.theme.error),
    };
    let mut spans = vec![
        Span::styled(format!(" {dot} {label} "), style),
        Span::styled(app.relay_url.clone(), app.theme.dim),
    ];
    if let Some(name) = &app.device_name {
        spans.push(Span::styled(
            format!("  device {}", silver_client::files::printable(name, 32)),
            app.theme.dim,
        ));
    }
    let pending = app.pending_count();
    if pending > 0 {
        spans.push(Span::styled(format!("  {pending} queued"), app.theme.warn));
    }
    match &app.toast {
        Some((text, _)) => {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(text.clone(), app.theme.toast));
        }
        None => {
            spans.push(Span::styled(
                format!("  {}", app.status_hint()),
                app.theme.dim,
            ));
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

/// The date rule's text: today and yesterday by name, the rest in full.
fn day_label(day: NaiveDate, today: NaiveDate) -> String {
    let full = day.format("%A %-d %B %Y");
    if day == today {
        format!(" Today, {full} ")
    } else if today.pred_opt() == Some(day) {
        format!(" Yesterday, {full} ")
    } else {
        format!(" {full} ")
    }
}

/// A rule with `text` in the middle, `width` columns wide.
fn separator(text: &str, width: usize, style: Style) -> Line<'static> {
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
        style,
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

    /// Replace what varies between runs (clocks, ids) so the screen can be
    /// compared with a stored snapshot.
    fn mask(screen: &str) -> String {
        const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let is_id = |t: &str| t.len() >= 40 && t.chars().all(|c| BASE58.contains(c));
        let is_short = |t: &str| {
            t.ends_with('…')
                && t.chars().count() == 9
                && t.chars().take(8).all(|c| BASE58.contains(c))
        };
        // Clocks depend on the time zone: "12:00" becomes "hh:mm" wherever
        // it appears, borders and all.
        let mut chars: Vec<char> = screen.chars().collect();
        let mut i = 0;
        while i + 5 <= chars.len() {
            let window = &chars[i..i + 5];
            let clock = window[2] == ':'
                && [0, 1, 3, 4].iter().all(|&j| window[j].is_ascii_digit())
                && (i == 0 || !chars[i - 1].is_ascii_digit())
                && (i + 5 == chars.len() || !chars[i + 5].is_ascii_digit());
            if clock {
                chars[i..i + 5].copy_from_slice(&['h', 'h', ':', 'm', 'm']);
                i += 5;
            } else {
                i += 1;
            }
        }
        let screen: String = chars.into_iter().collect();
        screen
            .lines()
            .map(|line| {
                line.split(' ')
                    .map(|t| {
                        if is_id(t) {
                            "<id>"
                        } else if is_short(t) {
                            "<short>…"
                        } else {
                            t
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The main screen, drawn into a test backend and compared with
    /// `tests/snapshots/main.txt`. Run with `UPDATE_SNAPSHOTS=1` to accept
    /// a changed layout after looking at it.
    #[tokio::test]
    async fn the_main_screen_matches_its_snapshot() {
        use crate::app::{ChatLine, Connection};
        use ratatui::{Terminal, backend::TestBackend};
        use silver_client::{Client, ConnectOptions, Contact, ContactRequest, HeldMessage, Store};
        use silver_protocol::{Identity, Sequence};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let url = "ws://127.0.0.1:1/ws".to_owned();
        let (client, _events) =
            Client::spawn(url.clone(), Arc::new(identity), ConnectOptions::default()).unwrap();
        let mut app = App::new(
            store,
            client,
            url,
            false,
            1,
            crate::glyphs::UNICODE,
            crate::theme::Theme::dark(),
            crate::app::AtRest::Passphrase,
        )
        .unwrap();
        app.connection = Connection::Connected;
        // Fixed identities, so the ids (and the title's width) do not vary.
        let fixed = |seed: u8| {
            Identity::from_secrets(&silver_protocol::identity::IdentitySecrets {
                signing_seed: [seed; 32],
                dh_secret: [seed; 32],
            })
            .user_id()
        };
        let bob = fixed(1);
        let carol = fixed(2);
        let mut contact = Contact::new(bob);
        contact.alias = Some("bob".into());
        contact.verified = true;
        app.contacts.push(contact);
        app.contacts.push(Contact::new(carol));
        // Noon UTC on a fixed day, so the date rule reads the same in any zone.
        let at = 1_735_732_800_000;
        app.threads.insert(
            bob,
            vec![
                ChatLine {
                    delivered: true,
                    receipt: Some(ReceiptKind::Read),
                    ..ChatLine::new("1", Direction::Sent, at, "hello bob")
                },
                ChatLine {
                    delivered: true,
                    ..ChatLine::new(
                        "2",
                        Direction::Received,
                        at + 60_000,
                        "hi alice, this is a longer message that has to wrap onto a second row so the hanging indent shows",
                    )
                },
                ChatLine::new(
                    "3",
                    Direction::Sent,
                    at + 120_000,
                    "[file] photo.jpg (1.2 MiB)",
                ),
            ],
        );
        app.unread.insert(carol, vec!["9".into()]);
        app.requests.push(ContactRequest {
            from: fixed(3),
            first_seen_ms: at,
            messages: vec![HeldMessage {
                id: "r1".into(),
                timestamp_ms: at,
                text: "can we talk?".into(),
                sequence: Sequence::default(),
                file: None,
                caps: Vec::new(),
            }],
        });
        app.selected = 1;
        app.input = "/se".into();
        app.cursor = 3;

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer();
        let mut got = String::new();
        for y in 0..buf.area.height {
            let line: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            got.push_str(line.trim_end());
            got.push('\n');
        }
        let got = mask(&got);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/main.txt");
        if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
            std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
            std::fs::write(path, &got).unwrap();
        }
        // A checkout with CRLF line endings (git on Windows) must not count.
        let want = std::fs::read_to_string(path)
            .unwrap_or_default()
            .replace('\r', "");
        if got != want {
            let first_difference = got
                .lines()
                .zip(want.lines())
                .position(|(g, w)| g != w)
                .map(|i| {
                    format!(
                        "first difference on row {}:\n{}\n{}",
                        i + 1,
                        got.lines().nth(i).unwrap_or(""),
                        want.lines().nth(i).unwrap_or("")
                    )
                })
                .unwrap_or_else(|| "the row count differs".to_owned());
            panic!(
                "the screen changed; look at it and run with UPDATE_SNAPSHOTS=1 to accept:\n{got}\n{first_difference}"
            );
        }
    }

    /// Everything a peer controls that reaches the screen (message text,
    /// an alias, a held request, a file name) is drawn through the cell
    /// buffer, which drops control characters, escape sequences and bidi
    /// overrides. This pins that down against the real terminal backend.
    #[tokio::test]
    async fn nothing_a_peer_sends_reaches_the_terminal_raw() {
        use crate::app::{ChatLine, Connection};
        use ratatui::{
            Terminal, TerminalOptions, Viewport, backend::CrosstermBackend, layout::Rect,
        };
        use silver_client::{Client, ConnectOptions, Contact, ContactRequest, HeldMessage, Store};
        use silver_protocol::{Identity, Sequence};
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        const NASTY: &str = "x\x1b]2;pwned\x07y\x1b]52;c;cHduZWQ=\x07z\x1b[31mred\r\n\x08\u{202e}gnp.exe\u{200b}\t\x1b\\";
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (identity, _) = store.load_or_create_identity().unwrap();
        let url = "ws://127.0.0.1:1/ws".to_owned();
        let (client, _events) =
            Client::spawn(url.clone(), Arc::new(identity), ConnectOptions::default()).unwrap();
        let mut app = App::new(
            store,
            client,
            url,
            false,
            1,
            crate::glyphs::UNICODE,
            crate::theme::Theme::dark(),
            crate::app::AtRest::Passphrase,
        )
        .unwrap();
        app.connection = Connection::Connected;
        let peer = Identity::generate().user_id();
        let mut contact = Contact::new(peer);
        contact.alias = Some(NASTY.to_owned());
        app.contacts.push(contact);
        app.threads.insert(
            peer,
            vec![ChatLine {
                delivered: true,
                ..ChatLine::new("1", Direction::Received, 1_735_732_800_000, NASTY)
            }],
        );
        app.requests.push(ContactRequest {
            from: Identity::generate().user_id(),
            first_seen_ms: 1_735_732_800_000,
            messages: vec![HeldMessage {
                id: "r1".into(),
                timestamp_ms: 1_735_732_800_000,
                text: NASTY.to_owned(),
                sequence: Sequence::default(),
                file: None,
                caps: Vec::new(),
            }],
        });
        app.input = NASTY.to_owned();

        let shared = Shared(Arc::new(Mutex::new(Vec::new())));
        // A fixed viewport, so drawing never asks the real terminal for its
        // size (there is no controlling tty in CI, and querying one would
        // fail); the crossterm backend still emits the escapes we inspect.
        let mut terminal = Terminal::with_options(
            CrosstermBackend::new(shared.clone()),
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(0, 0, 100, 24)),
            },
        )
        .unwrap();
        for pane in [1, 2, 0] {
            app.selected = pane;
            terminal.draw(|f| draw(f, &mut app)).unwrap();
        }
        app.help_open = true;
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let out = String::from_utf8_lossy(&shared.0.lock().unwrap()).into_owned();
        assert!(
            out.contains("pwned") && out.contains("red"),
            "the text itself is shown"
        );
        for forbidden in [
            "\x1b]2;", "\x1b]52;", "\x07", "\x1b[31m", "\r", "\x08", "\x1b\\",
        ] {
            assert!(
                !out.contains(forbidden),
                "{forbidden:?} reached the terminal"
            );
        }
        for forbidden in ['\u{202e}', '\u{200b}', '\t'] {
            let near = out.find(forbidden).map(|i| {
                let start = out[..i].char_indices().rev().nth(30).map_or(0, |(j, _)| j);
                let end = out[i..]
                    .char_indices()
                    .nth(30)
                    .map_or(out.len(), |(j, _)| i + j);
                out[start..end].to_owned()
            });
            assert!(
                !out.contains(forbidden),
                "{forbidden:?} reached the terminal near {near:?}"
            );
        }
    }

    #[test]
    fn date_rules_name_today_and_yesterday() {
        let today = NaiveDate::from_ymd_opt(2026, 9, 4).unwrap();
        assert_eq!(day_label(today, today), " Today, Friday 4 September 2026 ");
        let yesterday = NaiveDate::from_ymd_opt(2026, 9, 3).unwrap();
        assert_eq!(
            day_label(yesterday, today),
            " Yesterday, Thursday 3 September 2026 "
        );
        let earlier = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        assert_eq!(day_label(earlier, today), " Thursday 1 January 2026 ");
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
