//! Interactive browser: a scrolling list of devices, or of the services they
//! run, beside the full details of whichever device is selected.

use crate::arp::Flag;
use crate::history::{self, Change};
use crate::live::{Feed, Update};
use crate::omarchy::Follow;
use crate::palettes;
use crate::services::{self, Service, port_name};
use crate::theme::{Choice, Theme};
use crate::{Device, NOISY_SERVICES, PING, Scan, change_words, ip_alarm, kind_label};
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Cell, Clear, List, ListItem, ListState, Padding, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, TableState,
};
use ratatui::{DefaultTerminal, Frame};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

/// A terminal this wide shows the details beside the list; narrower, there's
/// only room for one of them.
const WIDE: u16 = 80;
const LABEL: usize = 13;
const FLASH: Duration = Duration::from_secs(2);

/// Every key, for the help screen.
const KEYS: &[(&str, &str)] = &[
    ("↑ ↓  j k", "Move through the list or the details"),
    ("g G  Home End", "First or last row"),
    ("1 2", "Devices or services"),
    ("Tab  → l", "Into the details"),
    ("Tab  ← h  Esc", "Back to the list"),
    ("Enter  y", "Copy the IP address (or address:port)"),
    ("w", "Open its web page in the browser"),
    ("c", "Copy all the details"),
    ("Enter  c", "In the details, copy the selected line"),
    ("PgUp PgDn", "Scroll details half a page"),
    ("Ctrl-u Ctrl-d", "Scroll details half a page"),
    ("J K", "Scroll details one line"),
    ("^n ^p ^v M-v", "Emacs: down / up, details page down / up"),
    ("M-< M->  ^g", "Emacs: first / last row, clear the filter"),
    ("/", "Filter the list"),
    ("s", "Sort the list by its next column"),
    ("Esc", "Clear the filter, or quit"),
    ("r", "Scan again"),
    ("+ → ~ -", "New, moved, renamed, missing since last time"),
    ("t", "Pick a color theme"),
    ("?", "Show this help"),
    ("q  Ctrl-c", "Quit"),
];

/// Which pane has the keyboard.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Focus {
    List,
    Details,
}

/// The column the list is in order of: the address, as scanned, or the
/// name or type (in the services view, the host or service).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Sort {
    Address,
    Name,
    Kind,
}

/// What a key asks of the loop that reads them.
#[derive(PartialEq, Debug)]
enum Action {
    Stay,
    Quit,
    Rescan,
}

/// One thing in the details pane: its lines, already wrapped, and what
/// copying it copies. Headings and gaps have nothing to copy, and the
/// cursor passes over them.
struct Item {
    lines: Vec<Line<'static>>,
    copy: Option<String>,
}

/// How the browser starts.
pub struct Settings {
    pub show_services: bool,
    /// Clicks and the wheel come to lsnet rather than the terminal.
    pub mouse: bool,
    /// The theme asked for, by flag or config.
    pub choice: Choice,
    /// Omarchy's palette, when running there: its theme wins, and is
    /// followed as it changes.
    pub omarchy: Option<omarchy_theme::Palette>,
}

/// Browse until the user quits, returning the latest scan and whether the
/// services view was showing.
pub fn run(start: impl Fn() -> Feed, settings: Settings) -> Result<(Scan, bool), String> {
    let mut terminal = ratatui::init();
    set_mouse(settings.mouse, true);
    let mut app = App::new(Scan::empty(), settings.show_services);
    app.choice = settings.choice;
    app.theme = match &settings.omarchy {
        Some(palette) => Theme::terminal(Some(palette)),
        None => Theme::chosen(settings.choice),
    };
    if settings.omarchy.is_some() {
        app.omarchy = true;
        app.follow = Follow::start();
    }
    if let Some(e) = palettes::errors().first() {
        app.flash = Some((format!("Skipped a theme: {e}"), Instant::now()));
    }
    app.feed = Some(start());
    app.has_results = false;
    let result = app
        .run(&mut terminal, &start)
        .map(|()| (app.scan, app.show_services));
    set_mouse(settings.mouse, false);
    ratatui::restore();
    result
}

/// The theme picker, while it's open: every choice, which is selected and
/// shown, and the one from before, for Esc to go back to.
struct Themes {
    choices: Vec<Choice>,
    list: ListState,
    before: Choice,
}

/// Turns mouse reporting on or off, if lsnet uses the mouse.
fn set_mouse(used: bool, on: bool) {
    use ratatui::crossterm::event::{DisableMouseCapture, EnableMouseCapture};
    use ratatui::crossterm::execute;
    if used {
        let _ = if on {
            execute!(std::io::stdout(), EnableMouseCapture)
        } else {
            execute!(std::io::stdout(), DisableMouseCapture)
        };
    }
}

/// Where the last draw put what a click can land on.
#[derive(Default)]
struct Hits {
    /// The header's tabs: from, to, and whether it's services.
    tabs: Vec<(u16, u16, bool)>,
    header_y: u16,
    /// The list's rows, under its column headings.
    list: Rect,
    /// The theme picker's rows.
    themes: Rect,
    /// The details' text, and the line each item starts on.
    details: Rect,
    item_starts: Vec<usize>,
    /// The footer's hints: from, to, and the key each stands for.
    footer: Vec<(u16, u16, KeyCode)>,
    footer_y: u16,
}

struct App {
    scan: Scan,
    services: Vec<Service>,
    show_services: bool,
    /// Indices into `scan.devices` (or `services`) that match the filter.
    visible: Vec<usize>,
    table: TableState,
    filter: String,
    typing_filter: bool,
    sort: Sort,
    detail_scroll: u16,
    focus: Focus,
    /// The item the details' cursor is on, while they have the keyboard.
    detail_cursor: usize,
    /// How wide the details' text was at the last draw.
    detail_width: u16,
    /// Rows of details that fit on screen, and how many there are, from the last draw.
    detail_height: u16,
    detail_lines: u16,
    flash: Option<(String, Instant)>,
    show_help: bool,
    /// Where results come from, while a scan runs or listens.
    feed: Option<Feed>,
    /// What the scan is doing, e.g. "waiting for ports 43%".
    status: String,
    /// Whether any results have arrived yet.
    has_results: bool,
    started: Instant,
    hits: Hits,
    theme: Theme,
    /// The theme asked for (or being previewed in the picker).
    choice: Choice,
    themes: Option<Themes>,
    /// Colors follow Omarchy's theme.
    omarchy: bool,
    follow: Option<Follow>,
}

impl App {
    fn new(scan: Scan, show_services: bool) -> App {
        let mut app = App {
            services: services::list(&scan.devices),
            show_services,
            scan,
            visible: Vec::new(),
            table: TableState::default(),
            filter: String::new(),
            typing_filter: false,
            sort: Sort::Address,
            detail_scroll: 0,
            focus: Focus::List,
            detail_cursor: 0,
            detail_width: 0,
            detail_height: 0,
            detail_lines: 0,
            flash: None,
            show_help: false,
            feed: None,
            status: String::new(),
            has_results: true,
            started: Instant::now(),
            hits: Hits::default(),
            theme: Theme::terminal(None),
            choice: Choice::Terminal,
            themes: None,
            omarchy: false,
            follow: None,
        };
        app.refilter(None);
        app
    }

    /// Take in whatever the scan has sent since last time.
    fn receive(&mut self) -> Result<(), String> {
        while let Some(feed) = &self.feed {
            let update = match feed.updates.try_recv() {
                Ok(u) => u,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.feed = None;
                    self.status.clear();
                    break;
                }
            };
            match update {
                Update::Status(s) => self.status = s,
                Update::Scan(scan) => {
                    let keep = self.selected_key();
                    self.services = services::list(&scan.devices);
                    self.scan = scan;
                    self.has_results = true;
                    self.refilter(keep);
                }
                Update::Failed(e) if !self.has_results => return Err(e),
                Update::Failed(e) => {
                    self.flash = Some((format!("Rescan failed: {e}"), Instant::now()));
                    self.status.clear();
                }
            }
        }
        Ok(())
    }

    fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        start: &impl Fn() -> Feed,
    ) -> Result<(), String> {
        loop {
            self.receive()?;
            if self
                .flash
                .as_ref()
                .is_some_and(|(_, at)| at.elapsed() > FLASH)
            {
                self.flash = None;
            }
            if let Some(palette) = self.follow.as_ref().and_then(Follow::changed) {
                self.theme = Theme::terminal(Some(&palette));
            }
            terminal
                .draw(|f| {
                    self.draw(f);
                    self.theme.paint(f.buffer_mut());
                })
                .map_err(|e| e.to_string())?;
            // Wake up now and then for the scan's news, the ping animation
            // and a flashed message expiring.
            if !event::poll(Duration::from_millis(120)).map_err(|e| e.to_string())? {
                continue;
            }
            let action = match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind == KeyEventKind::Press => self.key(emacs(key)),
                Event::Mouse(m) => self.mouse(m),
                _ => continue,
            };
            match action {
                Action::Stay => {}
                Action::Quit => return Ok(()),
                Action::Rescan => {
                    // The old scan stops listening when its feed is dropped.
                    self.feed = Some(start());
                    self.status = "scanning again".into();
                }
            }
        }
    }

    fn key(&mut self, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if self.show_help {
            // Any key closes the help, except that the quit keys still quit.
            self.show_help = false;
            if key.code == KeyCode::Char('q') || (key.code == KeyCode::Char('c') && ctrl) {
                return Action::Quit;
            }
            return Action::Stay;
        }
        if self.typing_filter {
            self.filter_key(key);
            return Action::Stay;
        }
        if self.themes.is_some() {
            self.themes_key(key);
            return Action::Stay;
        }
        if self.focus == Focus::Details && self.details_key(key, ctrl) {
            return Action::Stay;
        }
        match key.code {
            KeyCode::Char('c') if ctrl => return Action::Quit,
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.refilter(self.selected_key());
            }
            // Esc quits here, but C-g only ever cancels.
            KeyCode::Esc if key.modifiers == KeyModifiers::CONTROL => {}
            KeyCode::Esc => return Action::Quit,
            KeyCode::Down | KeyCode::Char('j') => {
                self.select(self.table.selected().map_or(0, |i| i + 1))
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.select(self.table.selected().map_or(0, |i| i.saturating_sub(1)))
            }
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
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Right | KeyCode::Char('l')
                if self.selected().is_some() =>
            {
                self.focus = Focus::Details;
                self.detail_cursor = 0;
                self.detail_scroll = 0;
            }
            KeyCode::Enter | KeyCode::Char('y') => self.copy_ip(),
            KeyCode::Char('w') => self.open_web(),
            KeyCode::Char('c') => self.copy_details(),
            KeyCode::Char('/') => {
                self.focus = Focus::List;
                self.typing_filter = true;
            }
            KeyCode::Char('s') => self.sort_by_next(),
            KeyCode::Char('1') => self.show(false),
            KeyCode::Char('2') => self.show(true),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('t') => self.open_themes(),
            KeyCode::Char('r') => return Action::Rescan,
            _ => {}
        }
        Action::Stay
    }

    /// A click or the wheel: on a tab, a footer hint, a row of the list or
    /// a line of the details. Clicking what's already selected copies it.
    fn mouse(&mut self, m: MouseEvent) -> Action {
        let at = Position {
            x: m.column,
            y: m.row,
        };
        let down = match m.kind {
            MouseEventKind::ScrollDown => 1,
            MouseEventKind::ScrollUp => -1,
            MouseEventKind::Down(MouseButton::Left) => 0,
            _ => return Action::Stay,
        };
        if self.show_help {
            self.show_help = false;
            return Action::Stay;
        }
        self.typing_filter = false;
        let hits = &self.hits;
        let row = |area: Rect| usize::from(at.y.saturating_sub(area.y));
        if let Some(themes) = &self.themes {
            // The wheel moves through the themes, a click shows one, and a
            // click on the one shown keeps it. A click outside goes back.
            let selected = themes.list.selected().unwrap_or(0);
            let clicked = themes.list.offset() + row(hits.themes);
            match down {
                0 if !hits.themes.contains(at) => self.themes_key(KeyCode::Esc.into()),
                0 if clicked == selected => self.themes_key(KeyCode::Enter.into()),
                0 => self.preview(clicked),
                _ => self.preview((selected as isize + down).max(0) as usize),
            }
            return Action::Stay;
        }
        if hits.list.contains(at) {
            let row = self.table.offset() + row(hits.list);
            if down != 0 {
                let i = self.table.selected().unwrap_or(0) as isize + down;
                self.select(i.max(0) as usize);
            } else if row < self.visible.len() {
                if self.focus == Focus::List && self.table.selected() == Some(row) {
                    self.copy_ip();
                }
                self.select(row);
                self.focus = Focus::List;
            }
        } else if hits.details.contains(at) {
            let line = usize::from(self.detail_scroll) + row(hits.details);
            let item = hits.item_starts.iter().take_while(|&&s| s <= line).count();
            match (down, self.focus) {
                (0, _) if item == 0 => {}
                (0, Focus::Details) if self.detail_cursor == item - 1 => self.copy_item(),
                (0, _) => {
                    let copyable = self
                        .items()
                        .get(item - 1)
                        .is_some_and(|it| it.copy.is_some());
                    if copyable {
                        self.focus = Focus::Details;
                        self.detail_cursor = item - 1;
                    }
                }
                (_, Focus::Details) => self.move_cursor(down),
                (_, Focus::List) => self.scroll_detail(3 * down as i32),
            }
        } else if down == 0 && at.y == hits.header_y {
            let tab = hits
                .tabs
                .iter()
                .find(|&&(from, to, _)| (from..to).contains(&at.x));
            if let Some(&(_, _, services)) = tab {
                self.show(services);
            }
        } else if down == 0 && at.y == hits.footer_y {
            let hint = hits
                .footer
                .iter()
                .find(|&&(from, to, _)| (from..to).contains(&at.x));
            if let Some(&(_, _, code)) = hint {
                return self.key(KeyEvent::from(code));
            }
        }
        Action::Stay
    }

    /// Opens the theme picker on the theme in use.
    fn open_themes(&mut self) {
        if self.omarchy {
            self.flash = Some(("Colors follow the Omarchy theme".into(), Instant::now()));
            return;
        }
        let choices: Vec<Choice> = std::iter::once(Choice::Terminal)
            .chain(palettes::names().map(Choice::Named))
            .collect();
        let at = choices.iter().position(|&c| c == self.choice).unwrap_or(0);
        self.themes = Some(Themes {
            choices,
            list: ListState::default().with_selected(Some(at)),
            before: self.choice,
        });
    }

    /// Shows the theme on row `i` of the picker.
    fn preview(&mut self, i: usize) {
        let Some(themes) = &mut self.themes else {
            return;
        };
        let i = i.min(themes.choices.len() - 1);
        themes.list.select(Some(i));
        let choice = themes.choices[i];
        if choice != self.choice {
            self.choice = choice;
            self.theme = Theme::chosen(choice);
        }
    }

    /// Keys in the theme picker: moving shows each theme, Enter keeps one
    /// (saving it to the config file), and Esc goes back to what was there.
    fn themes_key(&mut self, key: KeyEvent) {
        let Some(themes) = &self.themes else { return };
        let at = themes.list.selected().unwrap_or(0);
        let page = usize::from(self.hits.themes.height.max(2) - 1);
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.preview(at + 1),
            KeyCode::Up | KeyCode::Char('k') => self.preview(at.saturating_sub(1)),
            KeyCode::PageDown => self.preview(at + page),
            KeyCode::PageUp => self.preview(at.saturating_sub(page)),
            KeyCode::Home | KeyCode::Char('g') => self.preview(0),
            KeyCode::End | KeyCode::Char('G') => self.preview(usize::MAX),
            KeyCode::Enter => {
                self.themes = None;
                let name = self.choice.name();
                let message = match crate::config::save_theme(name) {
                    Ok(path) => format!("Theme {name}, saved in {}", path.display()),
                    Err(e) => format!("Theme {name}, but couldn't save it: {e}"),
                };
                self.flash = Some((message, Instant::now()));
            }
            KeyCode::Esc | KeyCode::Char('q' | 't') => {
                let before = themes.before;
                self.themes = None;
                if before != self.choice {
                    self.choice = before;
                    self.theme = Theme::chosen(before);
                }
            }
            _ => {}
        }
    }

    /// A key while the details have the keyboard, if it's one of theirs.
    fn details_key(&mut self, key: KeyEvent, ctrl: bool) -> bool {
        let page = (self.detail_height / 2).max(1) as isize;
        match key.code {
            KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Esc
            | KeyCode::Backspace
            | KeyCode::Left
            | KeyCode::Char('h') => self.focus = Focus::List,
            KeyCode::Down | KeyCode::Char('j' | 'J') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k' | 'K') => self.move_cursor(-1),
            KeyCode::Home | KeyCode::Char('g') => self.move_cursor(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_cursor(isize::MAX / 2),
            KeyCode::PageDown | KeyCode::Char('d') if key.code == KeyCode::PageDown || ctrl => {
                self.move_lines(page)
            }
            KeyCode::PageUp | KeyCode::Char('u') if key.code == KeyCode::PageUp || ctrl => {
                self.move_lines(-page)
            }
            KeyCode::Enter => self.copy_item(),
            KeyCode::Char('c') if !ctrl => self.copy_item(),
            _ => return false,
        }
        true
    }

    /// The devices (`false`) or the services (`true`), keeping the same
    /// device selected.
    fn show(&mut self, services: bool) {
        self.focus = Focus::List;
        if services != self.show_services {
            let keep = self.selected_key();
            self.show_services = services;
            self.refilter(keep);
        }
    }

    /// Sort by the next column, left to right and round again, keeping the
    /// same row selected.
    fn sort_by_next(&mut self) {
        let order = self.sort_order();
        let at = order.iter().position(|&s| s == self.sort).unwrap_or(0);
        self.sort = order[(at + 1) % order.len()];
        self.refilter(self.selected_key());
        let by = match self.headers()[(at + 1) % order.len()] {
            "IP" => "IP address".to_string(),
            heading => heading.to_lowercase(),
        };
        self.flash = Some((format!("Sorted by {by}"), Instant::now()));
    }

    /// What each of the list's columns sorts by, left to right.
    fn sort_order(&self) -> [Sort; 3] {
        if self.show_services {
            [Sort::Address, Sort::Kind, Sort::Name]
        } else {
            [Sort::Address, Sort::Name, Sort::Kind]
        }
    }

    /// The names of the list's columns, left to right.
    fn headers(&self) -> [&'static str; 3] {
        if self.show_services {
            ["ADDRESS", "SERVICE", "HOST"]
        } else {
            ["IP", "NAME", "TYPE"]
        }
    }

    /// The list's column headings, with the one it's sorted by marked.
    fn headings(&self) -> [String; 3] {
        let sorted = self.sort_order().map(|s| s == self.sort);
        let mut headings = self.headers().map(String::from);
        for (heading, sorted) in headings.iter_mut().zip(sorted) {
            if sorted {
                heading.push_str(" ▾");
            }
        }
        headings
    }

    /// Put the rows in `self.sort`'s order: by address they already are.
    /// Rows with no name or type come after those with one, and devices
    /// that didn't answer stay at the bottom.
    fn sort_visible(&mut self) {
        if self.sort == Sort::Address {
            return;
        }
        let devices = &self.scan.devices;
        let text = |i: usize| -> Option<String> {
            let (d, service) = if self.show_services {
                let s = &self.services[i];
                (&devices[s.device], s.name)
            } else {
                (&devices[i], None)
            };
            match self.sort {
                Sort::Kind if self.show_services => service.map(str::to_lowercase),
                Sort::Kind => kind_label(d).map(|k| k.to_lowercase()),
                _ => (d.name.as_deref())
                    .or(d.hostname.as_deref())
                    .or(d.vendor)
                    .map(str::to_lowercase),
            }
        };
        let missing = |i: usize| !self.show_services && devices[i].missing();
        // Stable, so rows that tie stay in address order.
        self.visible.sort_by_cached_key(|&i| {
            let text = text(i);
            (missing(i), text.is_none(), text)
        });
    }

    /// The selected device's details, as the pane last drew them.
    fn items(&self) -> Vec<Item> {
        self.selected()
            .map(|d| details(d, self.detail_width))
            .unwrap_or_default()
    }

    /// Move the details' cursor by `by` items that have something to copy.
    fn move_cursor(&mut self, by: isize) {
        let copyable: Vec<usize> = (self.items().iter().enumerate())
            .filter(|(_, it)| it.copy.is_some())
            .map(|(i, _)| i)
            .collect();
        let Some(&last) = copyable.last() else { return };
        let at = copyable
            .iter()
            .position(|&i| i >= self.detail_cursor)
            .unwrap_or(copyable.len() - 1);
        let to = (at as isize)
            .saturating_add(by)
            .clamp(0, copyable.len() as isize - 1);
        self.detail_cursor = copyable.get(to as usize).copied().unwrap_or(last);
    }

    /// Move the details' cursor about `by` lines, to the item there.
    fn move_lines(&mut self, by: isize) {
        let items = self.items();
        let starts: Vec<usize> = items
            .iter()
            .scan(0, |line, it| {
                let at = *line;
                *line += it.lines.len();
                Some(at)
            })
            .collect();
        let Some(&from) = starts.get(self.detail_cursor) else {
            return;
        };
        let target = (from as isize + by).max(0) as usize;
        let past = starts.iter().filter(|&&s| s <= target).count().max(1) - 1;
        self.detail_cursor = past;
        // Onto something copyable: on, in the way it's going.
        if items[past].copy.is_none() {
            self.move_cursor(if by < 0 { -1 } else { 0 });
        }
    }

    fn copy_item(&mut self) {
        let Some(text) = self
            .items()
            .into_iter()
            .nth(self.detail_cursor)
            .and_then(|it| it.copy)
        else {
            return;
        };
        copy_to_clipboard(&text);
        self.flash = Some((format!("Copied {text} to the clipboard"), Instant::now()));
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
        self.refilter(self.selected_key());
    }

    /// The device (and, in the services view, the port) on list row `row`.
    fn row_key(&self, row: usize) -> (Ipv4Addr, Option<u16>) {
        let i = self.visible[row];
        if self.show_services {
            (self.services[i].ip, Some(self.services[i].port))
        } else {
            (self.scan.devices[i].ip, None)
        }
    }

    fn selected_key(&self) -> Option<(Ipv4Addr, Option<u16>)> {
        self.table
            .selected()
            .filter(|&r| r < self.visible.len())
            .map(|r| self.row_key(r))
    }

    fn selected_service(&self) -> Option<&Service> {
        let i = *self.visible.get(self.table.selected()?)?;
        self.show_services.then(|| &self.services[i])
    }

    fn selected(&self) -> Option<&Device> {
        let i = *self.visible.get(self.table.selected()?)?;
        Some(if self.show_services {
            &self.scan.devices[self.services[i].device]
        } else {
            &self.scan.devices[i]
        })
    }

    fn selected_ip(&self) -> Option<Ipv4Addr> {
        self.selected().map(|d| d.ip)
    }

    /// Recompute which rows match the filter. `keep` stays selected if it
    /// still shows; otherwise the first row for the same device does.
    fn refilter(&mut self, keep: Option<(Ipv4Addr, Option<u16>)>) {
        let needle = self.filter.to_lowercase();
        let matches = |d: &Device, extra: String| {
            needle.is_empty() || (haystack(d) + &extra).contains(&needle)
        };
        self.visible = if self.show_services {
            (0..self.services.len())
                .filter(|&i| {
                    let s = &self.services[i];
                    matches(
                        &self.scan.devices[s.device],
                        format!("\n{}\n{}", s.address(), s.name.unwrap_or("")).to_lowercase(),
                    )
                })
                .collect()
        } else {
            (0..self.scan.devices.len())
                .filter(|&i| matches(&self.scan.devices[i], String::new()))
                .collect()
        };
        self.sort_visible();
        let rows = 0..self.visible.len();
        let pos = keep.and_then(|key| {
            rows.clone()
                .find(|&r| self.row_key(r) == key)
                .or_else(|| rows.clone().find(|&r| self.row_key(r).0 == key.0))
        });
        let before = self.selected_ip();
        self.table.select(if self.visible.is_empty() {
            None
        } else {
            Some(pos.unwrap_or(0))
        });
        if self.selected_ip() != before {
            self.detail_scroll = 0;
            self.detail_cursor = 0;
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
            self.detail_cursor = 0;
        }
    }

    fn scroll_detail(&mut self, by: i32) {
        let max = self.detail_lines.saturating_sub(self.detail_height) as i32;
        self.detail_scroll = (self.detail_scroll as i32 + by).clamp(0, max) as u16;
    }

    fn copy_ip(&mut self) {
        let text = match (self.selected_service(), self.selected_ip()) {
            (Some(s), _) => s.address(),
            (None, Some(ip)) => ip.to_string(),
            (None, None) => return,
        };
        copy_to_clipboard(&text);
        self.flash = Some((format!("Copied {text} to the clipboard"), Instant::now()));
    }

    /// The web page for the selected service, or the selected device's.
    fn web_url(&self) -> Option<String> {
        if self.show_services {
            return self.selected_service()?.url();
        }
        let device = *self.visible.get(self.table.selected()?)?;
        services::device_url(&self.services, &self.scan.devices, device)
    }

    fn open_web(&mut self) {
        let Some(url) = self.web_url() else { return };
        let message = match open_in_browser(&url) {
            Ok(()) => format!("Opening {url} in your browser"),
            Err(e) => format!("Couldn't open {url}: {e}"),
        };
        self.flash = Some((message, Instant::now()));
    }

    fn copy_details(&mut self) {
        let Some(d) = self.selected() else { return };
        let title = d.name.clone().unwrap_or_else(|| d.ip.to_string());
        copy_to_clipboard(&details_text(d));
        self.flash = Some((
            format!("Copied the details for {title} to the clipboard"),
            Instant::now(),
        ));
    }

    fn draw(&mut self, f: &mut Frame) {
        if !self.has_results {
            self.draw_scanning(f);
            return;
        }
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(f.area());
        self.hits = Hits {
            header_y: header.y,
            footer_y: footer.y,
            ..Hits::default()
        };
        let tabs = self.tabs();
        // Each tab's span, by where the spans before it end.
        let mut x = header.x;
        for (i, span) in tabs.spans.iter().enumerate() {
            let w = span.width() as u16;
            if i == 2 || i == 4 {
                self.hits.tabs.push((x, x + w, i == 4));
            }
            x += w;
        }
        f.render_widget(Paragraph::new(vec![tabs, self.summary()]), header);

        if body.width < WIDE {
            // Room for one: the list, or the details it went into.
            match self.focus {
                Focus::List => self.draw_either_list(f, body),
                Focus::Details => self.draw_detail(f, body),
            }
            self.draw_footer(f, footer);
            self.draw_overlays(f, body);
            return;
        }
        let [list, detail] = {
            // As wide as the list needs, up to 60%; details get the rest.
            let (first, name, last) = self.column_widths();
            let marks = if self.show_marks() { 2 } else { 0 };
            let list = 2 + 2 + marks + first + 1 + name + 1 + last;
            Layout::horizontal([
                Constraint::Length(list.min(body.width * 6 / 10)),
                Constraint::Fill(1),
            ])
            .areas(body)
        };
        self.draw_either_list(f, list);
        self.draw_detail(f, detail);
        self.draw_footer(f, footer);
        self.draw_overlays(f, body);
    }

    /// The help, or the theme picker, over the panes.
    fn draw_overlays(&mut self, f: &mut Frame, area: Rect) {
        if self.show_help {
            draw_help(f, area);
        }
        let Some(themes) = &mut self.themes else {
            return;
        };
        let items: Vec<ListItem> = themes
            .choices
            .iter()
            .map(|&c| ListItem::new(swatch(c, &self.theme)))
            .collect();
        let width = items.iter().map(ListItem::width).max().unwrap_or(0) as u16 + 6;
        let height = items.len() as u16 + 2;
        let popup = Rect {
            x: area.x + area.width.saturating_sub(width) / 2,
            y: area.y + area.height.saturating_sub(height) / 2,
            width: width.min(area.width),
            height: height.min(area.height),
        };
        f.render_widget(Clear, popup);
        let block = Block::bordered()
            .title(" Theme ".bold())
            .title_bottom(Line::from(" ⏎ keep  esc back ").dim())
            .border_style(Style::new().fg(self.theme.accent));
        self.hits.themes = block.inner(popup);
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ");
        f.render_stateful_widget(list, popup, &mut themes.list);
    }

    /// `lsnet` and its tabs.
    fn tabs(&self) -> Line<'static> {
        let mut spans = vec![" lsnet ".bold(), Span::raw(" ")];
        let tabs = [
            ("Devices", !self.show_services),
            ("Services", self.show_services),
        ];
        for (i, (name, on)) in tabs.into_iter().enumerate() {
            let tab = Span::raw(format!("{} {name}", i + 1));
            spans.push(if on {
                tab.bold().underlined()
            } else {
                tab.dim()
            });
            spans.push(Span::raw("  "));
        }
        Line::from(spans)
    }

    /// What was scanned, what the scan's doing, how many addresses are
    /// wrong (the details say why), and what it couldn't see.
    fn summary(&self) -> Line<'static> {
        let mut parts = vec![Span::raw(self.scan.summary.clone()).dim()];
        if !self.status.is_empty() {
            parts.push(Span::raw(self.status.clone()).cyan());
        }
        let flagged = |flag: Flag| {
            let present = self.scan.devices.iter().filter(|d| !d.missing());
            present.filter(|d| d.flags.contains(&flag)).count()
        };
        let problems = [
            (
                Flag::AddressConflict,
                "address conflict",
                "address conflicts",
            ),
            (
                Flag::LinkLocal,
                "self-assigned address",
                "self-assigned addresses",
            ),
            (
                Flag::OffSubnet,
                "off-subnet address",
                "off-subnet addresses",
            ),
        ];
        for (flag, one, many) in problems {
            let style = match flag {
                Flag::AddressConflict => Style::new().red(),
                Flag::LinkLocal | Flag::OffSubnet => Style::new().yellow(),
            };
            match flagged(flag) {
                0 => {}
                1 => parts.push(Span::styled(format!("1 {one}"), style)),
                n => parts.push(Span::styled(format!("{n} {many}"), style)),
            }
        }
        parts.extend(self.scan.caveats.iter().map(|c| Span::raw(c.clone()).dim()));
        let mut spans = vec![Span::raw(" ")];
        for (i, part) in parts.into_iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" · ").dim());
            }
            spans.push(part);
        }
        Line::from(spans)
    }

    fn draw_either_list(&mut self, f: &mut Frame, area: Rect) {
        // Inside the border, under the column headings.
        self.hits.list = Rect {
            x: area.x + 1,
            y: area.y + 2,
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(3),
        };
        if self.show_services {
            self.draw_services(f, area);
        } else {
            self.draw_list(f, area);
        }
    }

    /// A pane's border: in lsnet's accent while it has the keyboard, dim
    /// while the other pane does, as lsmd and lshn do.
    fn pane(&self, title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
        let border = if focused {
            Style::new().fg(self.theme.accent)
        } else {
            Style::new().dim()
        };
        Block::bordered().title(title).border_style(border)
    }

    /// The list's selected row: reversed while the list has the keyboard,
    /// and only bold while the details do.
    fn row_highlight(&self) -> Style {
        match self.focus {
            Focus::List => Style::new().add_modifier(Modifier::REVERSED),
            Focus::Details => Style::new().add_modifier(Modifier::BOLD),
        }
    }

    /// Widths of the list's three columns (IP, NAME, TYPE or ADDRESS, HOST,
    /// SERVICE), measured over every row so that filtering doesn't shift the
    /// layout. The services view shows SERVICE before HOST.
    fn column_widths(&self) -> (u16, u16, u16) {
        let widest = |header: &str, widths: &mut dyn Iterator<Item = usize>| {
            widths.max().unwrap_or(0).max(header.chars().count()) as u16
        };
        let devices = &self.scan.devices;
        let [first, second, third] = self.headings();
        if self.show_services {
            let s = &self.services;
            (
                widest(&first, &mut s.iter().map(|s| s.address().len())),
                widest(
                    &third,
                    &mut s.iter().map(|s| list_name(&devices[s.device]).width()),
                ),
                widest(&second, &mut s.iter().map(|s| s.name.map_or(0, str::len))),
            )
        } else {
            (
                15,
                widest(&second, &mut devices.iter().map(|d| list_name(d).width())),
                widest(
                    &third,
                    &mut devices
                        .iter()
                        .map(|d| kind_label(d).map_or(0, |k| k.chars().count())),
                ),
            )
        }
    }

    /// Whether the device list has a column for what changed since last time.
    fn show_marks(&self) -> bool {
        !self.show_services && self.scan.devices.iter().any(|d| !d.changes.is_empty())
    }

    /// The ping animation and what the scan is waiting for, until the first
    /// results arrive.
    fn draw_scanning(&self, f: &mut Frame) {
        let frame = (self.started.elapsed().as_millis() / 120) as usize % PING.len();
        let lines = [
            format!("{}  Scanning the network…", PING[frame]),
            self.status.clone(),
        ];
        let area = f.area();
        for (i, text) in lines.iter().enumerate() {
            let width = text.chars().count() as u16;
            let at = Rect {
                x: area.x + area.width.saturating_sub(width) / 2,
                y: area.y + area.height / 2 + i as u16,
                width: width.min(area.width),
                height: 1.min(area.height),
            };
            if at.y < area.y + area.height {
                f.render_widget(Paragraph::new(text.as_str()).dim(), at);
            }
        }
    }

    fn list_title(&self, what: &str, total: usize) -> String {
        // Devices that didn't answer are counted apart.
        let missing = |rows: &mut dyn Iterator<Item = usize>| {
            if self.show_services {
                0
            } else {
                rows.filter(|&i| self.scan.devices[i].missing()).count()
            }
        };
        let shown_missing = missing(&mut self.visible.iter().copied());
        let all_missing = missing(&mut (0..total));
        let shown = self.visible.len() - shown_missing;
        let count = if self.filter.is_empty() {
            shown.to_string()
        } else {
            format!("{shown} of {}", total - all_missing)
        };
        if shown_missing > 0 {
            format!(" {what} ({count} · {shown_missing} missing) ")
        } else {
            format!(" {what} ({count}) ")
        }
    }

    fn draw_services(&mut self, f: &mut Frame, area: Rect) {
        let (address_width, _, service_width) = self.column_widths();
        let rows = self.visible.iter().map(|&i| {
            let s = &self.services[i];
            Row::new([
                // The port's what tells one row from the next.
                Cell::from(Line::from(vec![
                    Span::raw(s.ip.to_string()).green(),
                    Span::raw(":").green().dim(),
                    Span::raw(s.port.to_string()).green().bold(),
                ])),
                Cell::from(s.name.map_or_else(|| Span::raw("·").dark_gray(), Span::raw)),
                Cell::from(list_name(&self.scan.devices[s.device])),
            ])
        });
        let widths = [
            Constraint::Length(address_width),
            Constraint::Length(service_width),
            Constraint::Fill(1),
        ];
        let table = Table::new(rows, widths)
            .header(Row::new(self.headings()).bold())
            .block(self.pane(
                self.list_title("Services", self.services.len()),
                self.focus == Focus::List,
            ))
            .row_highlight_style(self.row_highlight())
            .highlight_symbol("› ");
        f.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_list(&mut self, f: &mut Frame, area: Rect) {
        // TYPE gets the room it needs; NAME takes whatever is left.
        let (_, _, type_width) = self.column_widths();
        let marks = self.show_marks();
        let rows = self.visible.iter().map(|&i| {
            let d = &self.scan.devices[i];
            let kind_style = match (d.this_device, d.gateway) {
                (true, _) => Style::new().cyan(),
                (_, true) => Style::new().yellow(),
                _ => Style::new(),
            };
            let mut cells = vec![
                Cell::from(d.ip.to_string()).style(ip_style(d)),
                Cell::from(list_name(d)),
                Cell::from(kind_label(d).unwrap_or_default()).style(kind_style),
            ];
            if marks {
                cells.insert(0, Cell::from(marker(d)).yellow());
            }
            let row = Row::new(cells);
            // Devices that didn't answer this time are only a memory.
            if d.missing() { row.dark_gray() } else { row }
        });
        let mut widths = vec![
            Constraint::Length(15),
            Constraint::Fill(1),
            Constraint::Length(type_width),
        ];
        let mut header = self.headings().to_vec();
        if marks {
            widths.insert(0, Constraint::Length(1));
            header.insert(0, String::new());
        }
        let table = Table::new(rows, widths)
            .header(Row::new(header).bold())
            .block(self.pane(
                self.list_title("Devices", self.scan.devices.len()),
                self.focus == Focus::List,
            ))
            .row_highlight_style(self.row_highlight())
            .highlight_symbol("› ");
        f.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_detail(&mut self, f: &mut Frame, area: Rect) {
        let Some(d) = self.selected() else {
            let what = match (self.show_services, self.filter.is_empty()) {
                (true, true) => "No services found.",
                (true, false) => "No services match the filter.",
                (false, _) => "No devices match the filter.",
            };
            let empty =
                Paragraph::new(what.dim()).block(self.pane("", self.focus == Focus::Details));
            f.render_widget(empty, area);
            return;
        };
        let title = d.name.clone().unwrap_or_else(|| d.ip.to_string());
        let block = self
            .pane(format!(" {title} ").bold(), self.focus == Focus::Details)
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        let mut items = details(d, inner.width);
        self.detail_width = inner.width;
        self.detail_height = inner.height;
        let mut lines = Vec::new();
        if self.focus == Focus::Details {
            // The cursor on something to copy, and on screen.
            self.move_cursor(0);
            let start: usize = items[..self.detail_cursor.min(items.len())]
                .iter()
                .map(|it| it.lines.len())
                .sum();
            let len = items.get(self.detail_cursor).map_or(1, |it| it.lines.len());
            let (start, end) = (start as u16, (start + len) as u16);
            if end > self.detail_scroll + self.detail_height {
                self.detail_scroll = end.saturating_sub(self.detail_height);
            }
            self.detail_scroll = self.detail_scroll.min(start);
            if let Some(it) = items.get_mut(self.detail_cursor) {
                for line in &mut it.lines {
                    *line = std::mem::take(line).reversed();
                }
            }
        }
        self.hits.details = inner;
        self.hits.item_starts = items
            .iter()
            .scan(0, |line, it| {
                let at = *line;
                *line += it.lines.len();
                Some(at)
            })
            .collect();
        lines.extend(items.into_iter().flat_map(|it| it.lines));
        let para = Paragraph::new(lines);
        self.detail_lines = para.line_count(inner.width) as u16;
        if self.focus == Focus::List {
            self.scroll_detail(0);
        }
        f.render_widget(para.scroll((self.detail_scroll, 0)).block(block), area);
        if self.detail_lines > self.detail_height {
            let mut state =
                ScrollbarState::new(self.detail_lines.saturating_sub(self.detail_height) as usize)
                    .position(self.detail_scroll as usize);
            f.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight),
                area,
                &mut state,
            );
        }
    }

    fn draw_footer(&mut self, f: &mut Frame, area: Rect) {
        let line = if self.typing_filter {
            Line::from(vec![
                " /".bold(),
                Span::raw(self.filter.clone()),
                "▏".slow_blink(),
            ])
        } else if let Some((msg, _)) = &self.flash {
            Line::from(format!(" {msg}")).green()
        } else {
            // Each hint with how much it matters: on a narrow terminal the
            // least are dropped first, but never `?`, which lists them all.
            let copy = if self.show_services {
                "copy address"
            } else {
                "copy IP"
            };
            let mut keys = match self.focus {
                Focus::List => vec![
                    ("↑↓", "move", 0),
                    ("tab", "details", 7),
                    ("⏎", copy, 6),
                    ("c", "copy all", 5),
                    ("w", "open", 6),
                    ("/", "filter", 4),
                    ("esc", "clear filter", 4),
                    ("s", "sort", 3),
                    ("r", "rescan", 3),
                    ("t", "theme", 2),
                    ("?", "help", 9),
                    ("q", "quit", 1),
                ],
                Focus::Details => vec![
                    ("↑↓", "move", 0),
                    ("⏎ c", "copy line", 7),
                    ("y", "copy IP", 5),
                    ("w", "open", 6),
                    ("tab", "list", 7),
                    ("?", "help", 9),
                    ("q", "quit", 1),
                ],
            };
            // `w` only when there's a web page to open, `esc` only to clear
            // a filter, in place of starting one.
            let web = self.web_url().is_some();
            let filtered = !self.filter.is_empty();
            keys.retain(|&(k, _, _)| match k {
                "w" => web,
                "esc" => filtered,
                "/" => !filtered,
                _ => true,
            });
            let width = |keys: &[(&str, &str, u8)]| {
                let words: usize = keys
                    .iter()
                    .map(|(k, w, _)| k.chars().count() + 1 + w.len())
                    .sum();
                1 + words + 2 * keys.len().saturating_sub(1)
            };
            while width(&keys) > usize::from(area.width) {
                let Some(least) = (0..keys.len())
                    .filter(|&i| keys[i].2 < 9)
                    .min_by_key(|&i| keys[i].2)
                else {
                    break;
                };
                keys.remove(least);
            }
            let mut spans = vec![Span::raw(" ")];
            let mut x = area.x + 1;
            for (i, (k, what, _)) in keys.into_iter().enumerate() {
                if i > 0 {
                    spans.push(Span::raw("  "));
                    x += 2;
                }
                // Each hint clicks as its key.
                let w = (k.chars().count() + 1 + what.len()) as u16;
                let code = match k {
                    "tab" => Some(KeyCode::Tab),
                    "esc" => Some(KeyCode::Esc),
                    "⏎" | "⏎ c" => Some(KeyCode::Enter),
                    "↑↓" => None,
                    _ => k.chars().next().map(KeyCode::Char),
                };
                if let Some(code) = code {
                    self.hits.footer.push((x, x + w, code));
                }
                x += w;
                spans.push(k.bold());
                spans.push(Span::raw(format!(" {what}")).dim());
            }
            Line::from(spans)
        };
        f.render_widget(Paragraph::new(line), area);
    }
}

/// A theme's name and a strip of its colors, in exact colors that painting
/// leaves alone, and the same both ways, so the selected row's reversing
/// leaves them too.
fn swatch(choice: Choice, theme: &Theme) -> Line<'static> {
    let Choice::Named(name) = choice else {
        return Line::from(vec![
            Span::raw(format!("{:<18}", "terminal")),
            Span::raw("its own colors").dim(),
        ]);
    };
    let p = palettes::palette(name);
    let mut spans = vec![Span::raw(format!("{name:<18}"))];
    for c in [
        p.background(),
        p.red(),
        p.yellow(),
        p.green(),
        p.cyan(),
        p.blue(),
        p.magenta(),
        p.foreground(),
    ] {
        let c = theme.rgb(c.r, c.g, c.b);
        spans.push(Span::raw("██").fg(c).bg(c));
    }
    if !p.is_dark() {
        spans.push(Span::raw("  light").dim());
    }
    Line::from(spans)
}

fn draw_help(f: &mut Frame, area: Rect) {
    let key_width = KEYS
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
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
    let block = Block::bordered()
        .title(" Keys ".bold())
        .padding(Padding::horizontal(1));
    f.render_widget(Paragraph::new(lines).block(block), popup);
}

/// Emacs's movement keys, as the keys they stand for, so they work
/// wherever those do: C-n C-p for ↓ ↑, C-v M-v for a page, M-< M-> for the
/// ends, and C-g for Esc. C-g keeps Control, so it can cancel without quitting.
fn emacs(key: KeyEvent) -> KeyEvent {
    let ctrl = key.modifiers == KeyModifiers::CONTROL;
    let alt = key.modifiers.difference(KeyModifiers::SHIFT) == KeyModifiers::ALT;
    let code = match key.code {
        KeyCode::Char('n') if ctrl => KeyCode::Down,
        KeyCode::Char('p') if ctrl => KeyCode::Up,
        KeyCode::Char('v') if ctrl => KeyCode::PageDown,
        KeyCode::Char('v') if alt => KeyCode::PageUp,
        KeyCode::Char('<') if alt => KeyCode::Home,
        KeyCode::Char('>') if alt => KeyCode::End,
        KeyCode::Char('g') if ctrl => return KeyEvent::new(KeyCode::Esc, KeyModifiers::CONTROL),
        _ => return key,
    };
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// The browser as plain text, `width` wide and at least `height` tall, with
/// the row for `key` selected: the screens the README shows. It grows until
/// the details fit, so there's no scrollbar.
#[cfg(test)]
pub fn screen(
    scan: Scan,
    show_services: bool,
    key: (Ipv4Addr, Option<u16>),
    width: u16,
    mut height: u16,
) -> String {
    let mut app = App::new(scan, show_services);
    let row = (0..app.visible.len())
        .find(|&i| app.row_key(i) == key)
        .expect("the row to select is listed");
    app.select(row);
    let mut terminal = loop {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("a test terminal");
        terminal.draw(|f| app.draw(f)).expect("drawn");
        if app.detail_lines <= app.detail_height {
            break terminal;
        }
        height += app.detail_lines - app.detail_height;
    };
    let buffer = terminal.backend_mut().buffer().clone();
    let mut out = String::new();
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The device list's mark for what changed since last time.
fn marker(d: &Device) -> &'static str {
    match d.changes.first() {
        Some(Change::New) => "+",
        Some(Change::Moved { .. }) => "→",
        Some(Change::Renamed { .. }) => "~",
        Some(Change::Missing) => "-",
        None => "",
    }
}

/// Green, unless something is wrong with the address.
fn ip_style(d: &Device) -> Style {
    match ip_alarm(d) {
        Some(Flag::AddressConflict) => Style::new().red(),
        Some(_) => Style::new().yellow(),
        None => Style::new().green(),
    }
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
        Some(
            d.ipv6
                .iter()
                .map(Ipv6Addr::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    ];
    // "disagrees" and "names differ" find the devices whose sources do.
    let disputed = [
        (!d.type_disagrees.is_empty()).then(|| "type disagrees".to_string()),
        (!d.names_differ.is_empty()).then(|| format!("names differ\n{}", d.names_differ.join("\n"))),
    ];
    let flags = d
        .flags
        .iter()
        .map(|f| Some(flag_words(*f).to_string()))
        .chain([change_words(d)])
        .chain(disputed);
    fields
        .into_iter()
        .chain(flags)
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

/// The details pane's items for `d`, wrapped to `cols` with long values
/// continuing under the value column rather than the label.
fn details(d: &Device, cols: u16) -> Vec<Item> {
    let mut out = Vec::new();
    // One value column for the whole pane, wide enough for the longest Bonjour service type.
    let services = d.mdns.iter().flat_map(|m| m.services.keys());
    let width = services.map(String::len).max().unwrap_or(0).max(LABEL);
    let room = (cols as usize).saturating_sub(width + 1);
    let labelled = |label: Span<'static>, value: &str, style: Style| {
        let lines = wrap(value, room).into_iter().enumerate().map(|(i, part)| {
            let label = if i == 0 { label.clone() } else { Span::raw("") };
            let pad = " ".repeat(width + 1 - label.width().min(width));
            Line::from(vec![label, Span::raw(pad), Span::styled(part, style)])
        });
        lines.collect()
    };
    let row = |out: &mut Vec<Item>, label: Span<'static>, value: &str, style: Style| {
        out.push(Item {
            lines: labelled(label, value, style),
            copy: Some(value.to_string()),
        });
    };
    let field = |out: &mut Vec<Item>, label: &'static str, value: Option<String>| {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            row(out, label.dim(), &v, Style::new());
        }
    };
    // A line of text, wrapped to the pane.
    let text = |out: &mut Vec<Item>, text: &str, style: Style| {
        out.push(Item {
            lines: (wrap(text, cols as usize).into_iter())
                .map(|part| Line::styled(part, style))
                .collect(),
            copy: Some(text.to_string()),
        });
    };
    let heading = [kind_label(d), d.model.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
    if !heading.is_empty() {
        text(&mut out, &heading, Style::new().italic());
    }
    for flag in &d.flags {
        let style = match flag {
            Flag::AddressConflict => Style::new().red(),
            Flag::LinkLocal | Flag::OffSubnet => Style::new().yellow(),
        };
        text(&mut out, flag_explanation(*flag), style);
    }
    for change in &d.changes {
        let words = match change {
            Change::New => "New: not seen on this network before".to_string(),
            Change::Moved { from } => format!("Moved from {from}"),
            Change::Renamed { from } => format!("Renamed from {from}"),
            Change::Missing => "Didn't answer this time".to_string(),
        };
        text(&mut out, &words, Style::new().yellow());
    }
    if d.heard_later {
        text(
            &mut out,
            "Heard after the scan, while listening",
            Style::new().cyan(),
        );
    }
    // What decided the type and the name, and under each, whoever says
    // otherwise.
    let evidence = |out: &mut Vec<Item>, label: &'static str, value: &str| {
        row(out, label.dark_gray(), value, Style::new().dark_gray());
    };
    if let Some(from) = &d.type_from {
        evidence(&mut out, "Type from", from);
    }
    for other in &d.type_disagrees {
        evidence(&mut out, "Disagrees", other);
    }
    if let Some(from) = &d.name_from {
        evidence(&mut out, "Name from", from);
    }
    if !d.names_differ.is_empty() {
        evidence(&mut out, "Names differ", &d.names_differ.join(" · "));
    }
    if !out.is_empty() {
        gap(&mut out);
    }

    field(&mut out, "IP", Some(d.ip.to_string()));
    if !d.other_ips.is_empty() {
        let ips: Vec<String> = d.other_ips.iter().map(Ipv4Addr::to_string).collect();
        field(&mut out, "Also uses", Some(ips.join(" · ")));
    }
    if !d.ipv6.is_empty() {
        let ips: Vec<String> = d.ipv6.iter().map(Ipv6Addr::to_string).collect();
        field(&mut out, "IPv6", Some(ips.join(" · ")));
    }
    field(&mut out, "MAC", d.mac.clone());
    for mac in &d.other_macs {
        let vendor = mac.parse().ok().and_then(crate::oui::vendor);
        let text = match vendor {
            Some(v) => format!("{mac} ({v})"),
            None => mac.clone(),
        };
        row(&mut out, "Other MAC".dim(), &text, Style::new().red());
    }
    let vendor = match (d.vendor, d.randomized_mac) {
        (Some(v), _) => Some(v.to_string()),
        (None, true) => Some("unknown (private MAC)".into()),
        (None, false) => None,
    };
    field(&mut out, "Vendor", vendor);
    field(&mut out, "Hostname", d.hostname.clone());
    field(&mut out, "Ping", d.ping_ms.map(ping_text));
    if !d.changes.contains(&Change::New) {
        field(&mut out, "First seen", d.first_seen.map(history::date));
    }
    field(&mut out, "Last seen", d.last_seen.map(history::date));
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
        let (noisy, useful): (Vec<_>, Vec<_>) = m
            .services
            .iter()
            .partition(|(s, _)| NOISY_SERVICES.contains(&s.as_str()));
        for (dim, (svc, instance)) in useful
            .into_iter()
            .map(|s| (false, s))
            .chain(noisy.into_iter().map(|s| (true, s)))
        {
            let style = if dim {
                Style::new().dark_gray()
            } else {
                Style::new()
            };
            let label = Span::styled(
                svc.clone(),
                style.fg(if dim { Color::DarkGray } else { Color::Blue }),
            );
            row(&mut out, label, instance, style);
            // A TXT record copies its value alone.
            for (k, v) in m.txt.get(svc).into_iter().flatten() {
                out.push(Item {
                    lines: labelled(
                        Span::raw(""),
                        &format!("{k} = {v}"),
                        Style::new().dark_gray(),
                    ),
                    copy: Some(v.clone()),
                });
            }
        }
    }

    if let Some(s) = &d.ssdp {
        section(&mut out, "UPnP");
        field(&mut out, "Name", s.friendly_name.clone());
        field(&mut out, "Manufacturer", s.manufacturer.clone());
        let model = match (&s.model_name, &s.model_number) {
            (Some(name), Some(number)) if !name.contains(number.as_str()) => {
                Some(format!("{name} {number}"))
            }
            (Some(name), _) => Some(name.clone()),
            (None, number) => number.clone(),
        };
        field(&mut out, "Model", model);
        field(&mut out, "Device type", s.device_type.clone());
        field(&mut out, "Server", s.server.clone());
    }

    if let Some(k) = &d.kasa {
        section(&mut out, "TP-Link Kasa");
        field(&mut out, "Name", k.alias.clone());
        field(&mut out, "Model", k.model.clone());
        field(&mut out, "Description", k.description.clone());
        field(&mut out, "Device type", k.device_type.clone());
    }

    if let Some(n) = &d.netbios {
        section(&mut out, "NetBIOS");
        field(&mut out, "Name", Some(n.name.clone()));
        field(&mut out, "MAC", n.mac.clone());
    }

    if let Some(s) = &d.snmp {
        section(&mut out, "SNMP");
        field(&mut out, "Name", s.name.clone());
        field(&mut out, "Description", s.description.clone());
        field(&mut out, "Device", s.device.clone());
        let object_id = s.object_id.as_ref().map(|id| match s.maker() {
            Some(maker) => format!("{id} ({maker})"),
            None => id.clone(),
        });
        field(&mut out, "Object ID", object_id);
    }

    if let Some(h) = &d.http {
        section(&mut out, "Web (port 80)");
        field(&mut out, "Title", h.title.clone());
        field(&mut out, "Server", h.server.clone());
    }
    out
}

/// A round trip, to about two figures: "0.42 ms", "2.4 ms", "38 ms".
fn ping_text(ms: f64) -> String {
    match ms {
        ms if ms < 1.0 => format!("{ms:.2} ms"),
        ms if ms < 10.0 => format!("{ms:.1} ms"),
        ms => format!("{ms:.0} ms"),
    }
}

/// What the filter matches for a flag.
fn flag_words(flag: Flag) -> &'static str {
    match flag {
        Flag::LinkLocal => "link-local self-assigned",
        Flag::OffSubnet => "off-subnet",
        Flag::AddressConflict => "address conflict",
    }
}

fn flag_explanation(flag: Flag) -> &'static str {
    match flag {
        Flag::LinkLocal => "Self-assigned address: it asked for one over DHCP and got no answer",
        Flag::OffSubnet => {
            "Not on this network: usually a static address left over from another one"
        }
        Flag::AddressConflict => "Address conflict: more than one device answered for this address",
    }
}

fn section(out: &mut Vec<Item>, title: &'static str) {
    gap(out);
    out.push(Item {
        lines: vec![Line::from(title).bold().cyan()],
        copy: None,
    });
}

fn gap(out: &mut Vec<Item>) {
    out.push(Item {
        lines: vec![Line::default()],
        copy: None,
    });
}

/// The details pane as plain text for the clipboard: a title, then every
/// line unwrapped, with styling and trailing spaces dropped.
fn details_text(d: &Device) -> String {
    let title = d.name.clone().unwrap_or_else(|| d.ip.to_string());
    let lines = details(d, u16::MAX)
        .into_iter()
        .flat_map(|it| it.lines)
        .map(|line| {
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            text.trim_end().to_string()
        });
    let mut out = std::iter::once(title)
        .chain(lines)
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
    out
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
            let at = word[..fits]
                .rfind(['.', ':', '/', '-', '_', '@'])
                .map_or(fits, |i| i + 1);
            lines.push(word[..at].to_string());
            word = &word[at..];
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Use the platform's clipboard tool, or failing that ask the terminal to do
/// it (OSC 52), which also works over SSH in most modern terminals.
fn copy_to_clipboard(text: &str) {
    #[cfg(windows)]
    if crate::platform::set_clipboard(text) {
        return;
    }
    let tools: &[&[&str]] = if cfg!(target_os = "macos") {
        &[&["pbcopy"]]
    } else if cfg!(windows) {
        &[]
    } else {
        &[
            &["wl-copy"],
            &["xclip", "-selection", "clipboard"],
            &["xsel", "--clipboard", "--input"],
        ]
    };
    for tool in tools {
        let child = Command::new(tool[0])
            .args(&tool[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { continue };
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
        if wrote && child.wait().is_ok_and(|s| s.success()) {
            return;
        }
    }
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()));
    let _ = out.flush();
}

/// Open `url` with the system's default browser. On Windows this avoids
/// `cmd /c start`, which would treat an `&` as the start of a new command.
fn open_in_browser(url: &str) -> std::io::Result<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut c = Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(drop)
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
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
    fn emacs_keys_stand_for_the_usual_ones() {
        let k = |c, m| emacs(KeyEvent::new(KeyCode::Char(c), m)).code;
        assert_eq!(k('n', KeyModifiers::CONTROL), KeyCode::Down);
        assert_eq!(k('p', KeyModifiers::CONTROL), KeyCode::Up);
        assert_eq!(k('v', KeyModifiers::CONTROL), KeyCode::PageDown);
        assert_eq!(k('v', KeyModifiers::ALT), KeyCode::PageUp);
        assert_eq!(
            k('<', KeyModifiers::ALT | KeyModifiers::SHIFT),
            KeyCode::Home
        );
        assert_eq!(k('>', KeyModifiers::ALT), KeyCode::End);
        assert_eq!(k('g', KeyModifiers::CONTROL), KeyCode::Esc);
        // Plain letters, and Ctrl-c and Ctrl-d, are left alone.
        assert_eq!(k('n', KeyModifiers::NONE), KeyCode::Char('n'));
        assert_eq!(k('d', KeyModifiers::CONTROL), KeyCode::Char('d'));
    }

    #[test]
    fn wrap_breaks_at_spaces_then_mid_word() {
        assert_eq!(
            wrap("7000 AirPlay · 62078 iOS sync", 20),
            ["7000 AirPlay · 62078", "iOS sync"]
        );
        assert_eq!(
            wrap("fhrouter.mynetworksettings.com", 29),
            ["fhrouter.mynetworksettings.", "com"]
        );
        assert_eq!(
            wrap("urn:schemas-upnp-org:device:InternetGatewayDevice:2", 30),
            ["urn:schemas-upnp-org:device:", "InternetGatewayDevice:2"]
        );
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("short", 20), ["short"]);
        assert_eq!(wrap("", 20), [""]);
    }

    #[test]
    fn details_text_is_plain_and_unwrapped() {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, 1));
        d.name = Some("Home Router".into());
        d.hostname = Some("a-very-long-hostname.mynetworksettings.example.com".into());
        let mut m = crate::mdns::MdnsInfo::default();
        m.services.insert("airplay".into(), "Home Router".into());
        m.txt
            .entry("airplay".into())
            .or_default()
            .insert("model".into(), "AppleTV14,1".into());
        d.mdns = Some(m);
        let text = details_text(&d);
        assert!(text.starts_with("Home Router\n"));
        assert!(
            text.contains("Hostname      a-very-long-hostname.mynetworksettings.example.com\n")
        );
        assert!(text.contains("airplay       Home Router\n              model = AppleTV14,1\n"));
        assert!(text.lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn details_explain_flags_and_reasons() {
        let scan = crate::demo::scan();
        let text = |ip: &str| {
            let d = scan
                .devices
                .iter()
                .find(|d| d.ip.to_string() == ip)
                .unwrap();
            details_text(d)
        };
        let conflict = text("192.168.1.230");
        assert!(conflict.contains("Address conflict: more than one device"));
        assert!(conflict.contains("Other MAC     24:0a:c4:88:31:5b (Espressif)\n"));
        assert!(text("169.254.37.12").contains("Self-assigned address"));
        let tv = text("192.168.1.52");
        // The value column is as wide as "companion-link", the longest service.
        assert!(tv.contains("Type from      Bonjour airplay model = AppleTV14,1\n"));
        assert!(tv.contains("Name from      AirPlay\n"));
        let flagged = |words: &str| {
            scan.devices
                .iter()
                .filter(|d| haystack(d).contains(words))
                .count()
        };
        assert_eq!(flagged("conflict"), 1);
        assert_eq!(flagged("link-local"), 1);
        assert_eq!(flagged("off-subnet"), 1);
    }

    #[test]
    fn details_show_the_ping_and_who_disagrees() {
        let scan = crate::demo::scan();
        let pi = (scan.devices.iter())
            .find(|d| d.ip.to_string() == "192.168.1.130")
            .unwrap();
        let text = details_text(pi);
        assert!(text.contains("Name from     .local name\n"), "{text}");
        assert!(
            text.contains("Names differ  raspberrypi.local (Bonjour) · study.lan (reverse DNS)\n"),
            "{text}"
        );
        assert!(text.contains("Ping          0.62 ms\n"), "{text}");
        let differing = scan.devices.iter().filter(|d| haystack(d).contains("differ"));
        assert_eq!(differing.count(), 1);
        assert_eq!(ping_text(0.416), "0.42 ms");
        assert_eq!(ping_text(2.44), "2.4 ms");
        assert_eq!(ping_text(38.2), "38 ms");
    }

    /// The first column of each of the list's rows, as `app` has them.
    fn rows(app: &App) -> Vec<String> {
        (0..app.visible.len())
            .map(|r| match app.row_key(r) {
                (ip, Some(port)) => format!("{ip}:{port}"),
                (ip, None) => ip.to_string(),
            })
            .collect()
    }

    #[test]
    fn s_sorts_by_each_column_in_turn() {
        let mut scan = crate::demo::scan();
        crate::demo::memory().mark(&mut scan);
        let mut app = App::new(scan, false);
        let by_address = rows(&app);
        select_ip(&mut app, "192.168.1.52");
        assert!(drawn(&mut app, 120).contains("IP ▾"));

        press(&mut app, KeyCode::Char('s'));
        assert_eq!(app.sort, Sort::Name);
        assert!(drawn(&mut app, 120).contains("NAME ▾"));
        // The same device stays selected, wherever it went.
        assert_eq!(app.selected_ip().unwrap().to_string(), "192.168.1.52");
        let by_name = rows(&app);
        // "Alex's MacBook Pro", "alex-phone", … whatever their case.
        assert_eq!(by_name[..2], ["192.168.1.196", "192.168.1.112"]);
        // The device that didn't answer stays last, in every order.
        assert_eq!(by_name.last().unwrap(), "192.168.1.95");

        press(&mut app, KeyCode::Char('s'));
        assert_eq!(app.sort, Sort::Kind);
        let by_kind = rows(&app);
        // Audio devices first, in address order; the one with no type
        // after all that have one.
        assert_eq!(by_kind[..2], ["192.168.0.78", "192.168.1.77"]);
        assert_eq!(by_kind[by_kind.len() - 2], "192.168.1.203");
        assert_eq!(by_kind.last().unwrap(), "192.168.1.95");

        press(&mut app, KeyCode::Char('s'));
        assert_eq!(app.sort, Sort::Address);
        assert_eq!(rows(&app), by_address);
    }

    #[test]
    fn services_sort_by_their_own_columns() {
        let mut app = App::new(crate::demo::scan(), true);
        press(&mut app, KeyCode::Char('s'));
        assert_eq!(app.sort, Sort::Kind);
        let screen = drawn(&mut app, 120);
        assert!(screen.contains("SERVICE ▾"), "{screen}");
        assert_eq!(rows(&app)[..2], ["192.168.1.1:53", "192.168.1.150:53"]);
        press(&mut app, KeyCode::Char('s'));
        assert_eq!(app.sort, Sort::Name);
        assert!(drawn(&mut app, 120).contains("HOST ▾"));
        // A filter keeps the order.
        app.filter = "ssh".into();
        app.refilter(None);
        assert_eq!(
            rows(&app),
            [
                "192.168.1.196:22",
                "192.168.1.14:22",
                "192.168.1.150:22",
                "192.168.1.130:22"
            ]
        );
    }

    fn press(app: &mut App, code: KeyCode) -> Action {
        app.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    /// `app` drawn `width` columns wide, as text.
    fn drawn(app: &mut App, width: u16) -> String {
        let backend = ratatui::backend::TestBackend::new(width, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..40)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect()
    }

    fn select_ip(app: &mut App, ip: &str) {
        let row = (0..app.visible.len())
            .find(|&r| app.row_key(r).0.to_string() == ip)
            .unwrap();
        app.select(row);
    }

    #[test]
    fn one_and_two_are_tabs_for_devices_and_services() {
        let mut app = App::new(crate::demo::scan(), false);
        select_ip(&mut app, "192.168.1.14");
        assert!(drawn(&mut app, 120).starts_with(" lsnet  1 Devices  2 Services "));
        press(&mut app, KeyCode::Char('2'));
        assert!(app.show_services);
        assert_eq!(app.selected_ip().unwrap().to_string(), "192.168.1.14");
        press(&mut app, KeyCode::Char('2'));
        assert!(app.show_services, "2 stays on services");
        press(&mut app, KeyCode::Char('1'));
        assert!(!app.show_services);
    }

    #[test]
    fn the_second_line_sums_up_in_one() {
        let mut scan = crate::demo::scan();
        scan.changes = Some("since the last scan, 2 hours ago: 2 new".into());
        scan.caveats = vec!["tip: run with sudo".into()];
        let mut app = App::new(scan, false);
        let screen = drawn(&mut app, 200);
        let second = screen.lines().nth(1).unwrap().trim_end();
        assert_eq!(
            second,
            " 19 devices on 192.168.1.0/24 (demo) · 1 address conflict · \
             1 self-assigned address · 1 off-subnet address · tip: run with sudo"
        );
        assert!(!screen.contains("since the last scan"));
        assert!(screen.lines().nth(2).unwrap().starts_with('┌'));
    }

    #[test]
    fn the_details_take_the_keyboard_to_copy_a_line() {
        let mut app = App::new(crate::demo::scan(), false);
        select_ip(&mut app, "192.168.1.52");
        drawn(&mut app, 120);
        press(&mut app, KeyCode::Right);
        assert_eq!(app.focus, Focus::Details);
        let copy = |app: &mut App| {
            drawn(app, 120);
            app.items()
                .into_iter()
                .nth(app.detail_cursor)
                .and_then(|it| it.copy)
        };
        // From the heading, past where the type and name came from and over
        // the gap, to the IP, its IPv6 address and the MAC.
        assert_eq!(
            copy(&mut app).as_deref(),
            Some("TV / streamer · Apple TV 4K (3rd gen)")
        );
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(copy(&mut app).as_deref(), Some("192.168.1.52"));
        press(&mut app, KeyCode::Down);
        assert_eq!(copy(&mut app).as_deref(), Some("fe80::1c9f:4a2e:7d31:b8c6"));
        press(&mut app, KeyCode::Down);
        assert_eq!(copy(&mut app).as_deref(), Some("f0:18:98:3c:62:8d"));
        // A TXT record copies only its value.
        while copy(&mut app).as_deref() != Some("Living Room") {
            press(&mut app, KeyCode::Down);
        }
        press(&mut app, KeyCode::Down);
        assert_eq!(copy(&mut app).as_deref(), Some("AppleTV14,1"));
        // The end, and on screen.
        press(&mut app, KeyCode::End);
        let last = copy(&mut app);
        press(&mut app, KeyCode::Down);
        assert_eq!(copy(&mut app), last);
        // j and k move the cursor, not the list.
        assert_eq!(app.selected_ip().unwrap().to_string(), "192.168.1.52");
        // Esc goes back rather than quitting, and Tab goes back and forth.
        assert_eq!(press(&mut app, KeyCode::Esc), Action::Stay);
        assert_eq!(app.focus, Focus::List);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::Details);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::List);
        // Moving down the list, then in again: the cursor's back at the top.
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('l'));
        assert_eq!(app.detail_cursor, 0);
    }

    #[test]
    fn w_opens_a_web_page_when_there_is_one() {
        let mut app = App::new(crate::demo::scan(), false);
        // A Synology: DSM's page, not port 80's.
        select_ip(&mut app, "192.168.1.14");
        assert_eq!(app.web_url().as_deref(), Some("https://192.168.1.14:5001/"));
        assert!(drawn(&mut app, 124).contains(" w open "));
        // A phone has none, and no `w` in the footer.
        select_ip(&mut app, "192.168.1.112");
        assert_eq!(app.web_url(), None);
        assert!(!drawn(&mut app, 124).contains(" w open "));
        // A service: its own page, or none for SSH.
        press(&mut app, KeyCode::Char('2'));
        let plex = (0..app.visible.len())
            .find(|&r| app.row_key(r) == ("192.168.1.14".parse().unwrap(), Some(32400)))
            .unwrap();
        app.select(plex);
        assert_eq!(
            app.web_url().as_deref(),
            Some("http://192.168.1.14:32400/web")
        );
        let ssh = (0..app.visible.len())
            .find(|&r| app.row_key(r).1 == Some(22))
            .unwrap();
        app.select(ssh);
        assert_eq!(app.web_url(), None);
    }

    #[test]
    fn the_footer_fits_dropping_the_least_needed() {
        let footer = |app: &mut App, width| {
            let screen = drawn(app, width);
            screen.lines().nth(39).unwrap().trim_end().to_string()
        };
        let mut app = App::new(crate::demo::scan(), false);
        select_ip(&mut app, "192.168.1.14");
        // Wide, every hint.
        assert_eq!(
            footer(&mut app, 124),
            " ↑↓ move  tab details  ⏎ copy IP  c copy all  w open  / filter  s sort  r rescan  t theme  ? help  q quit"
        );
        // Narrower, the obvious ones go first; help stays.
        for focus in [Focus::List, Focus::Details] {
            app.focus = focus;
            for show_services in [false, true] {
                app.show(show_services);
                app.focus = focus;
                for width in [80, 60, 40, 20] {
                    let line = footer(&mut app, width);
                    assert!(line.contains("? help"), "{width}: {line}");
                    assert!(
                        line.chars().count() <= usize::from(width),
                        "{width}: {line}"
                    );
                }
            }
        }
        app.focus = Focus::List;
        app.show(false);
        assert_eq!(
            footer(&mut app, 80),
            " tab details  ⏎ copy IP  c copy all  w open  / filter  s sort  r rescan  ? help"
        );
        // Filtering, esc clears it in place of / starting one.
        app.filter = "nas".into();
        assert!(footer(&mut app, 124).contains("esc clear filter  s sort  r rescan"));
    }

    fn click(app: &mut App, x: u16, y: u16) -> Action {
        app.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        })
    }

    /// Where `text` is on screen, as drawn `width` wide.
    fn find(app: &mut App, width: u16, text: &str) -> (u16, u16) {
        let screen = drawn(app, width);
        screen
            .lines()
            .enumerate()
            .find_map(|(y, line)| {
                let at = line.find(text)?;
                Some((line[..at].chars().count() as u16, y as u16))
            })
            .unwrap_or_else(|| panic!("{text:?} isn't on screen:\n{screen}"))
    }

    #[test]
    fn clicks_switch_tabs_panes_and_rows() {
        let mut app = App::new(crate::demo::scan(), false);
        // The Services tab.
        let (x, y) = find(&mut app, 124, "2 Services");
        click(&mut app, x + 3, y);
        assert!(app.show_services);
        let (x, y) = find(&mut app, 124, "1 Devices");
        click(&mut app, x, y);
        assert!(!app.show_services);
        // A row of the list selects it.
        let (x, y) = find(&mut app, 124, "192.168.1.52 ");
        click(&mut app, x, y);
        assert_eq!(app.selected_ip().unwrap().to_string(), "192.168.1.52");
        assert_eq!(app.focus, Focus::List);
        // A line of the details puts the cursor on it.
        let (x, y) = find(&mut app, 124, "f0:18:98:3c:62:8d");
        click(&mut app, x, y);
        assert_eq!(app.focus, Focus::Details);
        let item = app.items().into_iter().nth(app.detail_cursor).unwrap();
        assert_eq!(item.copy.as_deref(), Some("f0:18:98:3c:62:8d"));
        // A heading has nothing to copy, so nothing happens.
        let cursor = app.detail_cursor;
        let (x, y) = find(&mut app, 124, "Bonjour (mDNS)");
        click(&mut app, x, y);
        assert_eq!(app.detail_cursor, cursor);
        // The wheel moves the cursor while the details have it.
        app.mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.detail_cursor, cursor + 1);
        // A footer hint clicks as its key: `tab list` goes back.
        drawn(&mut app, 124);
        let (x, y) = find(&mut app, 124, "tab list");
        click(&mut app, x, y);
        assert_eq!(app.focus, Focus::List);
        // The wheel over the list moves down it.
        let (x, y) = find(&mut app, 124, "192.168.1.52    Living Room");
        app.mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.selected_ip().unwrap().to_string(), "192.168.1.60");
    }

    #[test]
    fn the_pane_with_the_keyboard_is_outlined() {
        let mut app = App::new(crate::demo::scan(), false);
        // The top-left corners of the list and of the details.
        let corners = |app: &mut App| {
            let backend = ratatui::backend::TestBackend::new(124, 40);
            let mut terminal = ratatui::Terminal::new(backend).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            let buffer = terminal.backend().buffer().clone();
            let x = (0..124)
                .find(|&x| x > 0 && buffer[(x, 2)].symbol() == "┌")
                .unwrap();
            (buffer[(0, 2)].style(), buffer[(x, 2)].style())
        };
        let (list, details) = corners(&mut app);
        assert_eq!(list.fg, Some(Color::Cyan));
        assert!(details.add_modifier.contains(Modifier::DIM));
        press(&mut app, KeyCode::Tab);
        let (list, details) = corners(&mut app);
        assert!(list.add_modifier.contains(Modifier::DIM));
        assert_eq!(details.fg, Some(Color::Cyan));
    }

    #[test]
    fn the_theme_picker_previews_and_goes_back() {
        let mut app = App::new(crate::demo::scan(), false);
        press(&mut app, KeyCode::Char('t'));
        let screen = drawn(&mut app, 124);
        assert!(
            screen.contains(" Theme ") && screen.contains("tokyo-night"),
            "{screen}"
        );
        assert!(screen.contains("amber") && screen.contains("hn"));
        // Moving shows each theme, painted, with its accent on the panes.
        press(&mut app, KeyCode::Down);
        let first = palettes::names().next().unwrap();
        assert_eq!(app.choice, Choice::Named(first));
        assert_ne!(app.theme.accent, Color::Cyan);
        // Keys go to the picker, not the list.
        let row = app.table.selected();
        press(&mut app, KeyCode::Down);
        assert_eq!(app.table.selected(), row);
        // Esc goes back to the terminal's colors.
        press(&mut app, KeyCode::Esc);
        assert!(app.themes.is_none());
        assert_eq!(app.choice, Choice::Terminal);
        assert_eq!(app.theme.accent, Color::Cyan);
        // The wheel moves through it; a click outside goes back.
        press(&mut app, KeyCode::Char('t'));
        drawn(&mut app, 124);
        let inside = app.hits.themes;
        app.mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: inside.x,
            row: inside.y,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.choice, Choice::Named(first));
        click(&mut app, 0, 0);
        assert!(app.themes.is_none());
        assert_eq!(app.choice, Choice::Terminal);
        // On Omarchy, its theme wins.
        app.omarchy = true;
        press(&mut app, KeyCode::Char('t'));
        assert!(app.themes.is_none());
        assert!(app.flash.as_ref().unwrap().0.contains("Omarchy"));
    }

    #[test]
    fn narrow_shows_the_list_or_the_details() {
        let mut app = App::new(crate::demo::scan(), false);
        select_ip(&mut app, "192.168.1.52");
        let both = drawn(&mut app, WIDE);
        assert!(both.contains("┐┌"), "two panes at {WIDE}:\n{both}");
        let list = drawn(&mut app, WIDE - 1);
        assert!(!list.contains("┐┌") && list.contains(" Devices ("));
        press(&mut app, KeyCode::Right);
        let details = drawn(&mut app, WIDE - 1);
        assert!(!details.contains(" Devices (") && details.contains("f0:18:98:3c:62:8d"));
        press(&mut app, KeyCode::Left);
        assert!(drawn(&mut app, WIDE - 1).contains(" Devices ("));
    }

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b"192.168.1.1"), "MTkyLjE2OC4xLjE=");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"a"), "YQ==");
    }
}
