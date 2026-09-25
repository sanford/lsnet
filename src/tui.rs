//! Interactive browser: a scrolling device list beside the full details of
//! whichever device is selected.

use crate::{Device, NOISY_SERVICES, Scan, kind_label};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Cell, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
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

pub fn run(scan: impl Fn() -> Result<Scan, String>) -> Result<(), String> {
    let mut terminal = ratatui::init();
    let result = App::start(&mut terminal, &scan).and_then(|mut app| app.run(&mut terminal, &scan));
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
}

impl App {
    fn start(terminal: &mut DefaultTerminal, scan: &impl Fn() -> Result<Scan, String>) -> Result<App, String> {
        draw_scanning(terminal);
        let mut app = App {
            scan: scan()?,
            visible: Vec::new(),
            table: TableState::default(),
            filter: String::new(),
            typing_filter: false,
            detail_scroll: 0,
            detail_height: 0,
            detail_lines: 0,
            flash: None,
        };
        app.refilter(None);
        Ok(app)
    }

    fn run(&mut self, terminal: &mut DefaultTerminal, scan: &impl Fn() -> Result<Scan, String>) -> Result<(), String> {
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
                KeyCode::Char('r') => {
                    self.flash = Some(("Scanning…".into(), Instant::now()));
                    terminal.draw(|f| self.draw(f)).map_err(|e| e.to_string())?;
                    match scan() {
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
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body)
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(body)
        };
        self.draw_list(f, list);
        self.draw_detail(f, detail);
        self.draw_footer(f, footer);
    }

    fn draw_list(&mut self, f: &mut Frame, area: Rect) {
        let rows = self.visible.iter().map(|&i| {
            let d = &self.scan.devices[i];
            let name = match (&d.name, &d.hostname, d.vendor) {
                (Some(n), _, _) => Span::raw(n.clone()).bold(),
                (None, Some(h), _) => Span::raw(h.clone()),
                (None, None, Some(v)) => Span::raw(v).dim(),
                (None, None, None) => Span::raw("·").dark_gray(),
            };
            let kind_style = match (d.this_device, d.gateway) {
                (true, _) => Style::new().cyan(),
                (_, true) => Style::new().yellow(),
                _ => Style::new(),
            };
            Row::new([
                Cell::from(d.ip.to_string()).green(),
                Cell::from(name),
                Cell::from(kind_label(d).unwrap_or_default()).style(kind_style),
            ])
        });
        let title = if self.filter.is_empty() {
            format!(" Devices ({}) ", self.visible.len())
        } else {
            format!(" Devices ({} of {}) ", self.visible.len(), self.scan.devices.len())
        };
        let table = Table::new(rows, [Constraint::Length(15), Constraint::Fill(3), Constraint::Fill(2)])
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
        let para = Paragraph::new(details(d)).wrap(Wrap { trim: false });
        let block = Block::bordered().title(format!(" {title} ").bold()).padding(Padding::horizontal(1));
        let inner = block.inner(area);
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
                ("⏎/y", "copy IP"),
                ("PgUp/PgDn", "scroll details"),
                ("/", "filter"),
                ("r", "rescan"),
                ("q", "quit"),
            ];
            if !self.filter.is_empty() {
                keys.insert(4, ("esc", "clear filter"));
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

fn draw_scanning(terminal: &mut DefaultTerminal) {
    let _ = terminal.draw(|f| f.render_widget(Paragraph::new(" Scanning the network…".dim()), f.area()));
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

fn details(d: &Device) -> Vec<Line<'static>> {
    let mut out = Vec::new();
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
            out.push(Line::from(vec![
                Span::styled(format!("{svc:<LABEL$} "), style.fg(if dim { Color::DarkGray } else { Color::Blue })),
                Span::styled(instance.clone(), style),
            ]));
            for (k, v) in m.txt.get(svc).into_iter().flatten() {
                out.push(Line::styled(format!("{:LABEL$}  {k} = {v}", ""), Style::new().dark_gray()));
            }
        }
    }

    if let Some(s) = &d.ssdp {
        section(&mut out, "UPnP");
        field(&mut out, "Name", s.friendly_name.clone());
        field(&mut out, "Manufacturer", s.manufacturer.clone());
        let model = [s.model_name.clone(), s.model_number.clone()].into_iter().flatten().collect::<Vec<_>>();
        field(&mut out, "Model", (!model.is_empty()).then(|| model.join(" ")));
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

fn field(out: &mut Vec<Line<'static>>, label: &str, value: Option<String>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        out.push(Line::from(vec![format!("{label:<LABEL$} ").dim(), Span::raw(v)]));
    }
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
    fn base64_pads() {
        assert_eq!(base64(b"192.168.1.1"), "MTkyLjE2OC4xLjE=");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"a"), "YQ==");
    }
}

