//! Colors for the browser.
//!
//! lsnet draws in the terminal's own 16 colors, so by default it follows the
//! user's palette (and on Omarchy, the desktop theme, which sets it). A theme
//! picked by name paints everything in its palette's colors instead: the
//! terminal's 16 colors, its default foreground and (for most themes) its
//! background are swapped for the palette's as the screen is drawn, and its
//! accent outlines the pane with the keyboard.

use crate::palettes;
use omarchy_theme::Palette;
use ratatui::buffer::Buffer;
use ratatui::style::Color;
use std::str::FromStr;

/// What `--theme` and `theme =` pick: the terminal's own colors, or one of
/// the bundled themes (or the user's) by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Terminal,
    Named(&'static str),
}

impl FromStr for Choice {
    type Err = String;

    fn from_str(s: &str) -> Result<Choice, String> {
        if s == "terminal" {
            return Ok(Choice::Terminal);
        }
        palettes::find(s).map(Choice::Named).ok_or_else(|| {
            let names: Vec<_> = palettes::names().collect();
            format!(
                "unknown theme {s:?}: use terminal or one of {}",
                names.join(", ")
            )
        })
    }
}

impl Choice {
    /// As it's written in the config file.
    pub fn name(self) -> &'static str {
        match self {
            Choice::Terminal => "terminal",
            Choice::Named(name) => name,
        }
    }
}

impl<'de> serde::Deserialize<'de> for Choice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Choice, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A palette's colors for the terminal's: its 16 colors, and its default
/// foreground and background.
struct Paint {
    ansi: [Color; 16],
    fg: Color,
    bg: Color,
}

pub struct Theme {
    truecolor: bool,
    paint: Option<Paint>,
    /// What outlines the pane with the keyboard.
    pub accent: Color,
}

impl Theme {
    /// The terminal's own colors, with `palette`'s accent if there is one
    /// (Omarchy's, whose colors the terminal already has).
    pub fn terminal(palette: Option<&Palette>) -> Theme {
        let mut theme = Theme {
            truecolor: truecolor(),
            paint: None,
            accent: Color::Cyan,
        };
        if let Some(p) = palette {
            let a = p.accent();
            theme.accent = theme.rgb(a.r, a.g, a.b);
        }
        theme
    }

    /// The theme for `choice`.
    pub fn chosen(choice: Choice) -> Theme {
        let Choice::Named(name) = choice else {
            return Theme::terminal(None);
        };
        let palette = palettes::palette(name);
        let mut theme = Theme::terminal(Some(&palette));
        let rgb = |c: omarchy_theme::Rgb| theme.rgb(c.r, c.g, c.b);
        theme.paint = Some(Paint {
            ansi: std::array::from_fn(|i| rgb(palette.ansi(i as u8))),
            fg: rgb(palette.foreground()),
            // lshn's own themes keep the terminal's background.
            bg: if palettes::paints_background(name) {
                rgb(palette.background())
            } else {
                Color::Reset
            },
        });
        theme
    }

    /// Swaps the terminal's colors on screen for a painted theme's.
    pub fn paint(&self, buf: &mut Buffer) {
        let Some(paint) = &self.paint else { return };
        for cell in &mut buf.content {
            cell.fg = paint.color(cell.fg, paint.fg);
            cell.bg = paint.color(cell.bg, paint.bg);
        }
    }

    /// An exact color, or the nearest of 256 where the terminal has no more.
    pub fn rgb(&self, r: u8, g: u8, b: u8) -> Color {
        if self.truecolor {
            Color::Rgb(r, g, b)
        } else {
            Color::Indexed(ansi256(r, g, b))
        }
    }
}

impl Paint {
    /// The palette's color for `c`, with `default` for the terminal's
    /// default color.
    fn color(&self, c: Color, default: Color) -> Color {
        let i = match c {
            Color::Reset => return default,
            Color::Black => 0,
            Color::Red => 1,
            Color::Green => 2,
            Color::Yellow => 3,
            Color::Blue => 4,
            Color::Magenta => 5,
            Color::Cyan => 6,
            Color::Gray => 7,
            Color::DarkGray => 8,
            Color::LightRed => 9,
            Color::LightGreen => 10,
            Color::LightYellow => 11,
            Color::LightBlue => 12,
            Color::LightMagenta => 13,
            Color::LightCyan => 14,
            Color::White => 15,
            Color::Indexed(i) if i < 16 => i,
            other => return other,
        };
        self.ansi[usize::from(i)]
    }
}

fn truecolor() -> bool {
    std::env::var("COLORTERM")
        .is_ok_and(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"))
}

/// Nearest color in the xterm 256-color cube or gray ramp.
fn ansi256(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let nearest = |v: u8| {
        (0..6)
            .min_by_key(|&i| (LEVELS[i] as i32 - v as i32).abs())
            .unwrap() as u8
    };
    let (ri, gi, bi) = (nearest(r), nearest(g), nearest(b));
    let cube = 16 + 36 * ri + 6 * gi + bi;
    let cube_err = dist(
        (r, g, b),
        (
            LEVELS[ri as usize],
            LEVELS[gi as usize],
            LEVELS[bi as usize],
        ),
    );

    let avg = (r as u32 + g as u32 + b as u32) / 3;
    let gi = (avg.saturating_sub(8) / 10).min(23) as u8;
    let gv = 8 + 10 * gi;
    let gray_err = dist((r, g, b), (gv, gv, gv));

    if gray_err < cube_err { 232 + gi } else { cube }
}

fn dist(a: (u8, u8, u8), b: (u8, u8, u8)) -> i32 {
    let d = |x: u8, y: u8| (x as i32 - y as i32).pow(2);
    d(a.0, b.0) + d(a.1, b.1) + d(a.2, b.2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_terminal_or_a_theme() {
        assert_eq!("terminal".parse(), Ok(Choice::Terminal));
        assert_eq!("nord".parse(), Ok(Choice::Named("nord")));
        assert_eq!("amber".parse(), Ok(Choice::Named("amber")));
        let e = "blue".parse::<Choice>().unwrap_err();
        assert!(e.contains("tokyo-night") && e.contains("hn"), "{e}");
    }

    #[test]
    fn paints_the_terminal_colors() {
        let palette = palettes::palette("gruvbox");
        let theme = Theme::chosen(Choice::Named("gruvbox"));
        let mut buf = Buffer::empty(ratatui::layout::Rect::new(0, 0, 2, 1));
        buf[(1, 0)]
            .set_fg(Color::Magenta)
            .set_bg(Color::Rgb(1, 2, 3));
        theme.paint(&mut buf);
        let rgb = |c: omarchy_theme::Rgb| theme.rgb(c.r, c.g, c.b);
        assert_eq!(buf[(0, 0)].fg, rgb(palette.foreground()));
        assert_eq!(buf[(0, 0)].bg, rgb(palette.background()));
        assert_eq!(buf[(1, 0)].fg, rgb(palette.magenta()));
        assert_eq!(buf[(1, 0)].bg, Color::Rgb(1, 2, 3), "exact colors stay");
        assert_eq!(theme.accent, rgb(palette.accent()));
        // lshn's own keep the terminal's background.
        let amber = Theme::chosen(Choice::Named("amber"));
        let mut buf = Buffer::empty(ratatui::layout::Rect::new(0, 0, 1, 1));
        amber.paint(&mut buf);
        assert_eq!(buf[(0, 0)].bg, Color::Reset);
        // The terminal's own colors are left alone.
        let terminal = Theme::chosen(Choice::Terminal);
        let mut buf = Buffer::empty(ratatui::layout::Rect::new(0, 0, 1, 1));
        buf[(0, 0)].set_fg(Color::Green);
        terminal.paint(&mut buf);
        assert_eq!(buf[(0, 0)].fg, Color::Green);
        assert_eq!(terminal.accent, Color::Cyan);
    }

    #[test]
    fn maps_to_256_colors() {
        assert_eq!(ansi256(0, 0, 0), 16);
        assert_eq!(ansi256(255, 0, 0), 196);
        assert_eq!(ansi256(0x2b, 0x2f, 0x37), 236);
    }
}
