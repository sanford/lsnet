//! Interactive browser: a scrolling device list beside the full details of
//! whichever device is selected.

use crate::{Device, NOISY_SERVICES, Scan, animate, kind_label};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Cell, Clear, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Below this width the details go under the list instead of beside it.
const SIDE_BY_SIDE: u16 = 100;
const LABEL: usize = 13;
const FLASH: Duration = Duration::from_secs(2);

/// Every key, for the help screen.
const KEYS: &[(&str, &str)] = &[
    ("↑ ↓  j k", "Move through the list"),
    ("g G  Home End", "First or last device"),
    ("Enter  y", "Copy the IP address"),
    ("PgUp PgDn", "Scroll details half a page"),
    ("Ctrl-u Ctrl-d", "Scroll details half a page"),
    ("J K", "Scroll details one line"),
    ("/", "Filter the list"),
    ("Esc", "Clear the filter, or quit"),
    ("r", "Scan again"),
    ("h  ?", "Show this help"),
    ("q  Ctrl-c", "Quit"),
];

/// Browse until the user quits, returning the latest scan.
pub fn run(scan: impl Fn() -> Result<Scan, String> + Sync) -> Result<Scan, String> {
    let mut terminal = ratatui::init();
    let result = App::start(&mut terminal, &scan)
        .and_then(|mut app| app.run(&mut terminal, &scan).map(|()| app.scan));
    ratatui::restore();
    result
}

struct App {
    scan: Scan,
    /// Indices into `scan.devices` that match the filter.
    visible: Vec<usize>,
    table: TableState,
    filter: String,
    typing_filter: bool,
    detail_scroll: u16,
    /// Rows of details that fit on screen, and how many there are, from the last draw.
    detail_height: u16,
    detail_lines: u16,
    flash: Option<(String, Instant)>,
    show_help: bool,
}

impl App {
    fn start(terminal: &mut DefaultTerminal, scan: &(impl Fn() -> Result<Scan, String> + Sync)) -> Result<App, String> {
        let scan = animate(scan, |ping| draw_scanning(terminal, ping))?;
        let mut app = App {
            scan,
            visible: Vec::new(),
            table: TableState::default(),
            filter: String::new(),
            typing_filter: false,
            detail_scroll: 0,
            detail_height: 0,
            detail_lines: 0,
            flash: None,
            show_help: false,
        };
        app.refilter(None);
        Ok(app)
    }

    fn run(&mut self, terminal: &mut DefaultTerminal, scan: &(impl Fn() -> Result<Scan, String> + Sync)) -> Result<(), String> {
        loop {
            if self.flash.as_ref().is_some_and(|(_, at)| at.elapsed() > FLASH) {
                self.flash = None;
            }
            terminal.draw(|f| self.draw(f)).map_err(|e| e.to_string())?;
            // Wake up now and then so a flashed message can expire.
            if !event::poll(Duration::from_millis(250)).map_err(|e| e.to_string())? {
                continue;
            }
            let Event::Key(key) = event::read().map_err(|e| e.to_string())? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if self.show_help {
                // Any key closes the help, except that the quit keys still quit.
                self.show_help = false;
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    return Ok(());
                }
                continue;
            }
            if self.typing_filter {
                self.filter_key(key);
                continue;
            }
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Char('c') if ctrl => return Ok(()),
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Esc if !self.filter.is_empty() => {
                    self.filter.clear();
                    self.refilter(self.selected_ip());
                }
                KeyCode::Esc => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => self.select(self.table.selected().map_or(0, |i| i + 1)),
                KeyCode::Up | KeyCode::Char('k') => self.select(self.table.selected().map_or(0, |i| i.saturating_sub(1))),
                KeyCode::Home | KeyCode::Char('g') => self.select(0),
                KeyCode::End | KeyCode::Char('G') => self.select(usize::MAX),
                KeyCode::PageDown | KeyCode::Char('d') if key.code == KeyCode::PageDown || ctrl => {
                    self.scroll_detail(self.detail_height as i32 / 2)
                }
                KeyCode::PageUp | KeyCode::Char('u') if key.code == KeyCode::PageUp || ctrl => {
                    self.scroll_detail(-(self.detail_height as i32 / 2))
                }
                KeyCode::Char('J') => self.scroll_detail(1),
                KeyCode::Char('K') => self.scroll_detail(-1),
                KeyCode::Enter | KeyCode::Char('y') => self.copy_ip(),
                KeyCode::Char('/') => self.typing_filter = true,
                KeyCode::Char('h' | '?') => self.show_help = true,
                KeyCode::Char('r') => {
                    let result = animate(scan, |ping| {
                        self.flash = Some((format!("{ping}  Scanning…"), Instant::now()));
                        let _ = terminal.draw(|f| self.draw(f));
                    });
                    match result {
                        Ok(s) => {
                            let keep = self.selected_ip();
                            self.scan = s;
                            self.refilter(keep);
                            self.flash = None;
                        }
                        Err(e) => self.flash = Some((format!("Rescan failed: {e}"), Instant::now())),
                    }
                }
                _ => {}
            }
        }
    }

    fn filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.typing_filter = false,
            KeyCode::Esc => {
                self.typing_filter = false;
                self.filter.clear();
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.typing_filter = false;
                self.filter.clear();
            }
            KeyCode::Char(c) => self.filter.push(c),
            _ => return,
        }
        self.refilter(self.selected_ip());
    }

    fn selected(&self) -> Option<&Device> {
        self.table.selected().and_then(|i| self.visible.get(i)).map(|&i| &self.scan.devices[i])
    }

    fn selected_ip(&self) -> Option<Ipv4Addr> {
        self.selected().map(|d| d.ip)
    }

    /// Recompute which devices match the filter, keeping `keep` selected if it still shows.
    fn refilter(&mut self, keep: Option<Ipv4Addr>) {
        let needle = self.filter.to_lowercase();
        self.visible = (0..self.scan.devices.len())
            .filter(|&i| needle.is_empty() || haystack(&self.scan.devices[i]).contains(&needle))
            .collect();
        let pos = keep.and_then(|ip| self.visible.iter().position(|&i| self.scan.devices[i].ip == ip));
        let before = self.selected_ip();
        self.table.select(if self.visible.is_empty() { None } else { Some(pos.unwrap_or(0)) });
        if self.selected_ip() != before {
            self.detail_scroll = 0;
        }
    }

    fn select(&mut self, i: usize) {
        if self.visible.is_empty() {
            return;
        }
        let i = i.min(self.visible.len() - 1);
        if self.table.selected() != Some(i) {
            self.table.select(Some(i));
            self.detail_scroll = 0;
        }
    }

    fn scroll_detail(&mut self, by: i32) {
        let max = self.detail_lines.saturating_sub(self.detail_height) as i32;
        self.detail_scroll = (self.detail_scroll as i32 + by).clamp(0, max) as u16;
    }

    fn copy_ip(&mut self) {
        let Some(ip) = self.selected_ip() else { return };
        copy_to_clipboard(&ip.to_string());
        self.flash = Some((format!("Copied {ip} to the clipboard"), Instant::now()));
    }

    fn draw(&mut self, f: &mut Frame) {
        let notes = self.scan.notes.len() as u16;
        let [header, body, footer] =
            Layout::vertical([Constraint::Length(1 + notes), Constraint::Fill(1), Constraint::Length(1)]).areas(f.area());

        let mut head = vec![Line::from(vec![
            " lsnet ".bold(),
            Span::raw(" "),
            Span::raw(self.scan.summary.clone()).dim(),
        ])];
        head.extend(self.scan.notes.iter().map(|n| Line::from(format!(" {n}")).dim()));
        f.render_widget(Paragraph::new(head), header);

        let [list, detail] = if body.width >= SIDE_BY_SIDE {
            // As wide as the list needs, up to 60%; details get the rest.
            let (name, kind) = self.column_widths();
            let list = 2 + 2 + 15 + 1 + name + 1 + kind;
            Layout::horizontal([Constraint::Length(list.min(body.width * 6 / 10)), Constraint::Fill(1)]).areas(body)
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(body)
        };
        self.draw_list(f, list);
        self.draw_detail(f, detail);
        self.draw_footer(f, footer);
        if self.show_help {
            draw_help(f, body);
        }
    }

    /// Widths of the NAME and TYPE columns, measured over every device so
    /// that filtering doesn't shift the layout.
    fn column_widths(&self) -> (u16, u16) {
        let widest = |header: &str, width: &dyn Fn(&Device) -> usize| {
            self.scan.devices.iter().map(width).max().unwrap_or(0).max(header.len()) as u16
        };
        (
            widest("NAME", &|d| list_name(d).width()),
            widest("TYPE", &|d| kind_label(d).map_or(0, |k| k.chars().count())),
        )
    }

    fn draw_list(&mut self, f: &mut Frame, area: Rect) {
        // TYPE gets the room it needs; NAME takes whatever is left.
        let (_, type_width) = self.column_widths();
        let rows = self.visible.iter().map(|&i| {
            let d = &self.scan.devices[i];
            let kind_style = match (d.this_device, d.gateway) {
                (true, _) => Style::new().cyan(),
                (_, true) => Style::new().yellow(),
                _ => Style::new(),
            };
            Row::new([
                Cell::from(d.ip.to_string()).green(),
                Cell::from(list_name(d)),
                Cell::from(kind_label(d).unwrap_or_default()).style(kind_style),
            ])
        });
        let title = if self.filter.is_empty() {
            format!(" Devices ({}) ", self.visible.len())
        } else {
            format!(" Devices ({} of {}) ", self.visible.len(), self.scan.devices.len())
        };
        let table = Table::new(rows, [Constraint::Length(15), Constraint::Fill(1), Constraint::Length(type_width)])
            .header(Row::new(["IP", "NAME", "TYPE"]).bold())
            .block(Block::bordered().title(title))
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ");
        f.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_detail(&mut self, f: &mut Frame, area: Rect) {
        let Some(d) = self.selected() else {
            let empty = Paragraph::new("No devices match the filter.".dim()).block(Block::bordered());
            f.render_widget(empty, area);
            return;
        };
        let title = d.name.clone().unwrap_or_else(|| d.ip.to_string());
        let block = Block::bordered().title(format!(" {title} ").bold()).padding(Padding::horizontal(1));
        let inner = block.inner(area);
        let para = Paragraph::new(details(d, inner.width)).wrap(Wrap { trim: false });
        self.detail_lines = para.line_count(inner.width) as u16;
        self.detail_height = inner.height;
        self.scroll_detail(0);
        f.render_widget(
            para.scroll((self.detail_scroll, 0)).block(block),
            area,
        );
        if self.detail_lines > self.detail_height {
            let mut state = ScrollbarState::new(self.detail_lines.saturating_sub(self.detail_height) as usize)
                .position(self.detail_scroll as usize);
            f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut state);
        }
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let line = if self.typing_filter {
            Line::from(vec![" /".bold(), Span::raw(self.filter.clone()), "▏".slow_blink()])
        } else if let Some((msg, _)) = &self.flash {
            Line::from(format!(" {msg}")).green()
        } else {
            let mut keys = vec![
                ("↑↓", "move"),
                ("⏎", "copy IP"),
                ("/", "filter"),
                ("r", "rescan"),
                ("?", "help"),
                ("q", "quit"),
            ];
            if !self.filter.is_empty() {
                keys.insert(3, ("esc", "clear filter"));
            }
            let mut spans = vec![Span::raw(" ")];
            for (k, what) in keys {
                spans.push(k.bold());
                spans.push(Span::raw(format!(" {what}  ")).dim());
            }
            Line::from(spans)
        };
        f.render_widget(Paragraph::new(line), area);
    }
}

fn draw_help(f: &mut Frame, area: Rect) {
    let key_width = KEYS.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
    let mut lines: Vec<Line> = KEYS
        .iter()
        .map(|(k, what)| Line::from(vec![format!("{k:<key_width$}   ").bold(), Span::raw(*what)]))
        .collect();
    lines.push(Line::default());
    lines.push(Line::from("Press any key to close").dim());
    let width = lines.iter().map(Line::width).max().unwrap_or(0) as u16 + 4;
    let height = lines.len() as u16 + 2;
    let popup = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    };
    f.render_widget(Clear, popup);
    let block = Block::bordered().title(" Keys ".bold()).padding(Padding::horizontal(1));
    f.render_widget(Paragraph::new(lines).block(block), popup);
}

/// A device's name for the list, falling back to its hostname, then its vendor.
fn list_name(d: &Device) -> Span<'static> {
    match (&d.name, &d.hostname, d.vendor) {
        (Some(n), _, _) => Span::raw(n.clone()).bold(),
        (None, Some(h), _) => Span::raw(h.clone()),
        (None, None, Some(v)) => Span::raw(v).dim(),
        (None, None, None) => Span::raw("·").dark_gray(),
    }
}

fn draw_scanning(terminal: &mut DefaultTerminal, ping: &str) {
    let _ = terminal.draw(|f| {
        let text = format!("{ping}  Scanning the network…");
        let width = text.chars().count() as u16;
        let area = f.area();
        let at = Rect {
            x: area.x + area.width.saturating_sub(width) / 2,
            y: area.y + area.height / 2,
            width: width.min(area.width),
            height: 1.min(area.height),
        };
        f.render_widget(Paragraph::new(text).dim(), at);
    });
}

/// Everything the filter matches against, lowercased.
fn haystack(d: &Device) -> String {
    let fields = [
        Some(d.ip.to_string()),
        d.name.clone(),
        kind_label(d),
        d.model.clone(),
        d.vendor.map(String::from),
        d.mac.clone(),
        d.hostname.clone(),
    ];
    fields.into_iter().flatten().collect::<Vec<_>>().join("\n").to_lowercase()
}

/// The details pane's lines for `d`, wrapped to `cols` with long values
/// continuing under the value column rather than the label.
fn details(d: &Device, cols: u16) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    // One value column for the whole pane, wide enough for the longest Bonjour service type.
    let services = d.mdns.iter().flat_map(|m| m.services.keys());
    let width = services.map(String::len).max().unwrap_or(0).max(LABEL);
    let room = (cols as usize).saturating_sub(width + 1);
    let row = |out: &mut Vec<Line<'static>>, label: Span<'static>, value: &str, style: Style| {
        for (i, part) in wrap(value, room).into_iter().enumerate() {
            let label = if i == 0 { label.clone() } else { Span::raw("") };
            let pad = " ".repeat(width + 1 - label.width().min(width));
            out.push(Line::from(vec![label, Span::raw(pad), Span::styled(part, style)]));
        }
    };
    let field = |out: &mut Vec<Line<'static>>, label: &'static str, value: Option<String>| {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            row(out, label.dim(), &v, Style::new());
        }
    };
    let heading = [kind_label(d), d.model.clone()].into_iter().flatten().collect::<Vec<_>>().join(" · ");
    if !heading.is_empty() {
        out.push(Line::from(heading).italic());
        out.push(Line::default());
    }

    field(&mut out, "IP", Some(d.ip.to_string()));
    field(&mut out, "MAC", d.mac.clone());
    let vendor = match (d.vendor, d.randomized_mac) {
        (Some(v), _) => Some(v.to_string()),
        (None, true) => Some("unknown (private MAC)".into()),
        (None, false) => None,
    };
    field(&mut out, "Vendor", vendor);
    field(&mut out, "Hostname", d.hostname.clone());
    if !d.open_ports.is_empty() {
        let ports = d
            .open_ports
            .iter()
            .map(|&p| match port_name(p) {
                Some(n) => format!("{p} {n}"),
                None => p.to_string(),
            })
            .collect::<Vec<_>>()
            .join(" · ");
        field(&mut out, "Open ports", Some(ports));
    }

    if let Some(m) = &d.mdns {
        section(&mut out, "Bonjour (mDNS)");
        field(&mut out, "Name", m.hostname.clone());
        // Services that identify the device first; generic infrastructure dimmed at the end.
        let (noisy, useful): (Vec<_>, Vec<_>) =
            m.services.iter().partition(|(s, _)| NOISY_SERVICES.contains(&s.as_str()));
        for (dim, (svc, instance)) in useful.into_iter().map(|s| (false, s)).chain(noisy.into_iter().map(|s| (true, s))) {
            let style = if dim { Style::new().dark_gray() } else { Style::new() };
            let label = Span::styled(svc.clone(), style.fg(if dim { Color::DarkGray } else { Color::Blue }));
            row(&mut out, label, instance, style);
            for (k, v) in m.txt.get(svc).into_iter().flatten() {
                row(&mut out, Span::raw(""), &format!("{k} = {v}"), Style::new().dark_gray());
            }
        }
    }

    if let Some(s) = &d.ssdp {
        section(&mut out, "UPnP");
        field(&mut out, "Name", s.friendly_name.clone());
        field(&mut out, "Manufacturer", s.manufacturer.clone());
        let model = match (&s.model_name, &s.model_number) {
            (Some(name), Some(number)) if !name.contains(number.as_str()) => Some(format!("{name} {number}")),
            (Some(name), _) => Some(name.clone()),
            (None, number) => number.clone(),
        };
        field(&mut out, "Model", model);
        field(&mut out, "Device type", s.device_type.clone());
        field(&mut out, "Server", s.server.clone());
    }

    if let Some(h) = &d.http {
        section(&mut out, "Web (port 80)");
        field(&mut out, "Title", h.title.clone());
        field(&mut out, "Server", h.server.clone());
    }
    out
}

fn section(out: &mut Vec<Line<'static>>, title: &'static str) {
    out.push(Line::default());
    out.push(Line::from(title).bold().cyan());
}

/// Break `text` into lines of at most `max` characters, at spaces where it can.
fn wrap(text: &str, max: usize) -> Vec<String> {
    let max = max.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for mut word in text.split(' ') {
        loop {
            let used = line.chars().count();
            if used + usize::from(used > 0) + word.chars().count() <= max {
                if used > 0 {
                    line.push(' ');
                }
                line.push_str(word);
                break;
            }
            if used > 0 {
                lines.push(std::mem::take(&mut line));
                continue;
            }
            // A word longer than a whole line gets split, after punctuation
            // if there's some (hostnames, URNs, paths), or else anywhere.
            let fits = word.char_indices().nth(max).map_or(word.len(), |(i, _)| i);
            let at = word[..fits].rfind(['.', ':', '/', '-', '_', '@']).map_or(fits, |i| i + 1);
            lines.push(word[..at].to_string());
            word = &word[at..];
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// What the ports `probe` checks usually mean.
fn port_name(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "SSH",
        80 => "HTTP",
        443 => "HTTPS",
        445 => "SMB",
        7000 => "AirPlay",
        8008 => "Cast",
        9100 => "printing",
        62078 => "iOS sync",
        _ => return None,
    })
}

/// Use the platform's clipboard tool, or failing that ask the terminal to do
/// it (OSC 52), which also works over SSH in most modern terminals.
fn copy_to_clipboard(text: &str) {
    let tools: &[&[&str]] = if cfg!(target_os = "macos") {
        &[&["pbcopy"]]
    } else {
        &[&["wl-copy"], &["xclip", "-selection", "clipboard"], &["xsel", "--clipboard", "--input"]]
    };
    for tool in tools {
        let child = Command::new(tool[0])
            .args(&tool[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { continue };
        let wrote = child.stdin.take().is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
        if wrote && child.wait().is_ok_and(|s| s.success()) {
            return;
        }
    }
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()));
    let _ = out.flush();
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_at_spaces_then_mid_word() {
        assert_eq!(wrap("7000 AirPlay · 62078 iOS sync", 20), ["7000 AirPlay · 62078", "iOS sync"]);
        assert_eq!(wrap("fhrouter.mynetworksettings.com", 29), ["fhrouter.mynetworksettings.", "com"]);
        assert_eq!(wrap("urn:schemas-upnp-org:device:InternetGatewayDevice:2", 30), [
            "urn:schemas-upnp-org:device:",
            "InternetGatewayDevice:2"
        ]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("short", 20), ["short"]);
        assert_eq!(wrap("", 20), [""]);
    }

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b"192.168.1.1"), "MTkyLjE2OC4xLjE=");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"a"), "YQ==");
    }
}

