use eframe::egui::{Key, Modifiers, Pos2, Rect};
pub fn position(pos: Pos2, rect: Rect, size: [u32; 2]) -> (u16, u16) {
    let x = ((pos.x - rect.left()) / rect.width() * size[0] as f32)
        .floor()
        .clamp(0.0, size[0].saturating_sub(1).min(65535) as f32);
    let y = ((pos.y - rect.top()) / rect.height() * size[1] as f32)
        .floor()
        .clamp(0.0, size[1].saturating_sub(1).min(65535) as f32);
    (x as u16, y as u16)
}
pub fn modifiers(m: Modifiers, native: bool) -> Vec<u32> {
    let mut result = Vec::new();
    if m.shift {
        result.push(0xffe1);
    }
    if m.ctrl {
        result.push(if native { 0xffe3 } else { 0xffeb });
    }
    if m.alt {
        result.push(0xffe7);
    }
    if m.mac_cmd {
        result.push(if native { 0xffeb } else { 0xffe3 });
    }
    result
}
pub fn keysym(key: Key, shift: bool) -> Option<u32> {
    let named = match key {
        Key::ArrowDown => 0xff54,
        Key::ArrowUp => 0xff52,
        Key::ArrowLeft => 0xff51,
        Key::ArrowRight => 0xff53,
        Key::Escape => 0xff1b,
        Key::Tab => 0xff09,
        Key::Backspace => 0xff08,
        Key::Enter => 0xff0d,
        Key::Insert => 0xff63,
        Key::Delete => 0xffff,
        Key::Home => 0xff50,
        Key::End => 0xff57,
        Key::PageUp => 0xff55,
        Key::PageDown => 0xff56,
        Key::F1 => 0xffbe,
        Key::F2 => 0xffbf,
        Key::F3 => 0xffc0,
        Key::F4 => 0xffc1,
        Key::F5 => 0xffc2,
        Key::F6 => 0xffc3,
        Key::F7 => 0xffc4,
        Key::F8 => 0xffc5,
        Key::F9 => 0xffc6,
        Key::F10 => 0xffc7,
        Key::F11 => 0xffc8,
        Key::F12 => 0xffc9,
        _ => 0,
    };
    if named != 0 {
        return Some(named);
    }
    let name = key.name();
    if name.len() == 1 {
        let c = name.as_bytes()[0];
        if c.is_ascii_alphabetic() {
            return Some(if shift {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            } as u32);
        }
        if c.is_ascii_digit() {
            return Some(if shift {
                b")!@#$%^&*("[(c - b'0') as usize]
            } else {
                c
            } as u32);
        }
    }
    let c = match key {
        Key::Space => ' ',
        Key::Minus => {
            if shift {
                '_'
            } else {
                '-'
            }
        }
        Key::Equals => {
            if shift {
                '+'
            } else {
                '='
            }
        }
        Key::OpenBracket => {
            if shift {
                '{'
            } else {
                '['
            }
        }
        Key::CloseBracket => {
            if shift {
                '}'
            } else {
                ']'
            }
        }
        Key::Backslash => {
            if shift {
                '|'
            } else {
                '\\'
            }
        }
        Key::Semicolon => {
            if shift {
                ':'
            } else {
                ';'
            }
        }
        Key::Quote => {
            if shift {
                '"'
            } else {
                '\''
            }
        }
        Key::Comma => {
            if shift {
                '<'
            } else {
                ','
            }
        }
        Key::Period => {
            if shift {
                '>'
            } else {
                '.'
            }
        }
        Key::Slash => {
            if shift {
                '?'
            } else {
                '/'
            }
        }
        Key::Backtick => {
            if shift {
                '~'
            } else {
                '`'
            }
        }
        _ => return None,
    };
    Some(c as u32)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn letterbox_coordinates_clamp_to_frame() {
        let rect = Rect::from_min_size(Pos2::new(100.0, 100.0), eframe::egui::vec2(960.0, 540.0));
        assert_eq!(
            position(Pos2::new(580.0, 370.0), rect, [1920, 1080]),
            (960, 540)
        );
        assert_eq!(
            position(Pos2::new(2000.0, 10.0), rect, [1920, 1080]),
            (1919, 0)
        );
    }
    #[test]
    fn shortcut_profile_maps_command_and_option() {
        let m = Modifiers {
            ctrl: true,
            alt: true,
            ..Modifiers::default()
        };
        assert_eq!(modifiers(m, false), vec![0xffeb, 0xffe7]);
        assert_eq!(modifiers(m, true), vec![0xffe3, 0xffe7]);
    }
    #[test]
    fn shifted_digits_and_unicode_keys() {
        assert_eq!(keysym(Key::Num2, true), Some('@' as u32));
        assert_eq!(keysym(Key::A, false), Some('a' as u32));
    }
}
