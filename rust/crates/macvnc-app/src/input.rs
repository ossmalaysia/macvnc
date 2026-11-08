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
pub const SHIFT: u32 = 0xffe1;
pub const CONTROL: u32 = 0xffe3;
pub const OPTION: u32 = 0xffe7;
pub const COMMAND: u32 = 0xffeb;
/// Physical modifier keys the GUI toolkit cannot tell apart. egui merges left
/// and right Ctrl and drops the Windows key entirely, which left the default
/// Ctrl → Command profile with no way to send the Mac's Control key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Physical {
    pub left_ctrl: bool,
    pub right_ctrl: bool,
    pub windows: bool,
}
/// Remote modifier keysyms for the current local state, matching the legacy
/// contract (docs/CONTRACTS.md):
/// - `ctrl-as-cmd`: left Ctrl → Command, right Ctrl → Control, Win → Control.
/// - `native`: Ctrl → Control, Win → Command.
///
/// `physical` is `None` where sides cannot be read; every Ctrl is then treated
/// as the left one. egui's combined Ctrl flag stays authoritative for whether a
/// Ctrl is down at all, so a stale side reading cannot latch a key on the Mac.
pub fn modifiers(m: Modifiers, native: bool, physical: Option<Physical>) -> Vec<u32> {
    let p = physical.unwrap_or_default();
    let (left_ctrl, right_ctrl) = match (m.ctrl, p.left_ctrl || p.right_ctrl) {
        (false, _) => (false, false),
        (true, true) => (p.left_ctrl, p.right_ctrl),
        (true, false) => (true, false),
    };
    let windows = p.windows || m.mac_cmd;
    let mut result = Vec::new();
    let mut push = |keysym: u32| {
        if !result.contains(&keysym) {
            result.push(keysym);
        }
    };
    if m.shift {
        push(SHIFT);
    }
    if native {
        if left_ctrl || right_ctrl {
            push(CONTROL);
        }
    } else {
        if left_ctrl {
            push(COMMAND);
        }
        if right_ctrl {
            push(CONTROL);
        }
    }
    if m.alt {
        push(OPTION);
    }
    if windows {
        push(if native { COMMAND } else { CONTROL });
    }
    result
}
/// Reads which side's Ctrl and whether a Windows key is down. `GetKeyState`
/// reflects the UI thread's message queue, so it agrees with the key events
/// egui has just delivered for this frame.
#[cfg(windows)]
pub fn physical_modifiers() -> Option<Physical> {
    #[link(name = "user32")]
    extern "system" {
        fn GetKeyState(virtual_key: i32) -> i16;
    }
    const VK_LWIN: i32 = 0x5b;
    const VK_RWIN: i32 = 0x5c;
    const VK_LCONTROL: i32 = 0xa2;
    const VK_RCONTROL: i32 = 0xa3;
    // SAFETY: GetKeyState takes a plain integer and has no pointer arguments.
    let down = |key| unsafe { GetKeyState(key) } < 0;
    Some(Physical {
        left_ctrl: down(VK_LCONTROL),
        right_ctrl: down(VK_RCONTROL),
        windows: down(VK_LWIN) || down(VK_RWIN),
    })
}
#[cfg(not(windows))]
pub fn physical_modifiers() -> Option<Physical> {
    None
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
        // egui reports these shifted symbols as their own logical keys
        // (Shift+1 arrives as Exclamationmark, not Num1), so map them directly.
        Key::Exclamationmark => '!',
        Key::Plus => '+',
        Key::Questionmark => '?',
        Key::OpenCurlyBracket => '{',
        Key::CloseCurlyBracket => '}',
        Key::Colon => ':',
        Key::Pipe => '|',
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
        assert_eq!(modifiers(m, false, None), vec![COMMAND, OPTION]);
        assert_eq!(modifiers(m, true, None), vec![CONTROL, OPTION]);
    }
    #[test]
    fn right_ctrl_and_windows_key_send_control_in_command_profile() {
        let ctrl = Modifiers {
            ctrl: true,
            ..Modifiers::default()
        };
        let right = Physical {
            right_ctrl: true,
            ..Physical::default()
        };
        assert_eq!(modifiers(ctrl, false, Some(right)), vec![CONTROL]);
        let both = Physical {
            left_ctrl: true,
            right_ctrl: true,
            ..Physical::default()
        };
        assert_eq!(modifiers(ctrl, false, Some(both)), vec![COMMAND, CONTROL]);
        let windows = Physical {
            windows: true,
            ..Physical::default()
        };
        assert_eq!(
            modifiers(Modifiers::default(), false, Some(windows)),
            vec![CONTROL]
        );
        assert_eq!(
            modifiers(Modifiers::default(), true, Some(windows)),
            vec![COMMAND]
        );
        // Right Ctrl plus Win in the command profile is still one Control.
        let right_and_windows = Physical {
            right_ctrl: true,
            windows: true,
            ..Physical::default()
        };
        assert_eq!(
            modifiers(ctrl, false, Some(right_and_windows)),
            vec![CONTROL]
        );
    }
    #[test]
    fn native_profile_sends_control_for_either_ctrl() {
        let ctrl = Modifiers {
            ctrl: true,
            ..Modifiers::default()
        };
        let right = Physical {
            right_ctrl: true,
            ..Physical::default()
        };
        assert_eq!(modifiers(ctrl, true, Some(right)), vec![CONTROL]);
    }
    #[test]
    fn stale_side_reading_never_latches_ctrl() {
        // egui says no Ctrl is down; a lagging side reading must not press one.
        let right = Physical {
            right_ctrl: true,
            ..Physical::default()
        };
        assert!(modifiers(Modifiers::default(), false, Some(right)).is_empty());
        // egui says Ctrl is down but no side registered yet: treat as left.
        let ctrl = Modifiers {
            ctrl: true,
            ..Modifiers::default()
        };
        assert_eq!(
            modifiers(ctrl, false, Some(Physical::default())),
            vec![COMMAND]
        );
    }
    #[test]
    fn shifted_digits_and_unicode_keys() {
        assert_eq!(keysym(Key::Num2, true), Some('@' as u32));
        assert_eq!(keysym(Key::A, false), Some('a' as u32));
    }
    #[test]
    fn logical_shifted_symbols_map_to_their_characters() {
        for (key, c) in [
            (Key::Exclamationmark, '!'),
            (Key::Plus, '+'),
            (Key::Questionmark, '?'),
            (Key::OpenCurlyBracket, '{'),
            (Key::CloseCurlyBracket, '}'),
            (Key::Colon, ':'),
            (Key::Pipe, '|'),
        ] {
            assert_eq!(keysym(key, true), Some(c as u32), "{key:?}");
        }
    }
}
