# Bug: `! + ? { } : |` do not reach the Mac

## Summary

Typing `!`, `+`, `?`, `{`, `}`, `:` or `|` in the remote view sends nothing to the
Mac. Every other shifted symbol (`@ # $ % ^ & * ( ) _ " < > ~`) works.

- **Component:** `rust/crates/macvnc-app/src/input.rs` — `keysym()`
- **Severity:** High. Breaks passwords, shell commands, code editing and URLs.
- **Platform:** Windows client (egui/eframe 0.31.1, winit) → macOS HP server
- **Workaround:** Paste the character. Pasting goes through `typed()`, which sends the
  character itself (as a keysym), not a key press.

## Steps to reproduce

1. Connect to the Mac and focus a text field.
2. Press Shift+1, Shift+=, Shift+/, Shift+[, Shift+], Shift+; or Shift+\\.
3. **Expected:** `! + ? { } : |` appear on the Mac.
   **Actual:** Nothing appears. Only Shift is pressed and released on the Mac.

## Root cause

1. On key down, egui-winit sets
   `active_key = logical_key.or(physical_key)`
   (`egui-winit-0.31.1/src/lib.rs:764`). The logical key comes from
   `egui::Key::from_name(<produced character>)`.
2. For Shift+1, winit reports the logical character `"!"`, and
   `Key::from_name("!")` returns **`Key::Exclamationmark`**
   (`egui-0.31.1/src/data/key.rs:356`). The same happens for `+ ? { } : |`.
   These are the only seven shifted symbols that egui gives their own `Key` variants.
3. `input::keysym()` has no match arm for these variants:
   - The `key.name().len() == 1` shortcut never matches them, because `name()`
     returns `"Exclamationmark"`, not `"!"`.
   - The final `match key` covers only the *unshifted* variants (`Num1`, `Equals`,
     `Slash`, `OpenBracket`, `CloseBracket`, `Semicolon`, `Backslash`), so it falls
     through to `_ => return None`.
4. In `App::remote_input` (`main.rs:364-379`), `None` means no key event is sent.
   ASCII `Event::Text` is ignored on purpose (`main.rs:412` only handles non-ASCII),
   so nothing else sends the character either. It is dropped without any error.

### Why other shifted symbols work

`@ # $ …` have no dedicated egui `Key`. `from_name("@")` returns `None`, so egui
falls back to the physical key (`Num2`). `keysym(Num2, shift=true)` then looks up the
shift table and returns `'@'`. The existing test only covers `Num2 + shift`, which is
why this gap was never caught.

## Proposed change

Map the seven logical-symbol keys straight to their characters. They are already
the shifted character, so the `shift` flag doesn't apply:

```rust
// input.rs, in the final `match key` of keysym()
        // egui reports these shifted symbols as their own logical keys
        // (Shift+1 arrives as Exclamationmark, not Num1), so map them directly.
        Key::Exclamationmark => '!',
        Key::Plus => '+',
        Key::Questionmark => '?',
        Key::OpenCurlyBracket => '{',
        Key::CloseCurlyBracket => '}',
        Key::Colon => ':',
        Key::Pipe => '|',
```

Regression test:

```rust
    #[test]
    fn logical_shifted_symbols_map_to_their_characters() {
        for (key, c) in [
            (Key::Exclamationmark, '!'), (Key::Plus, '+'), (Key::Questionmark, '?'),
            (Key::OpenCurlyBracket, '{'), (Key::CloseCurlyBracket, '}'),
            (Key::Colon, ':'), (Key::Pipe, '|'),
        ] {
            assert_eq!(keysym(key, true), Some(c as u32));
        }
    }
```

The rest of the key path already handles these keys correctly once they have a keysym:

- **Key release:** `self.pressed` is keyed by egui `Key`, so the release sends the same
  keysym that was pressed.
- **Shift:** Shift (0xffe1) is already down on the Mac. Sending a shifted keysym with
  Shift held is the same path that works for `@`.
- **Composed-text guard:** It only applies to non-ASCII text, so these keys are not
  affected.

### Alternative considered (not recommended now)

Use the `physical_key` field on `Event::Key` together with the shift table. This matches
how the existing `@ #` path behaves, but it assumes a US layout (for example, Shift+1 is
`!` only on US-style layouts). The logical mapping above follows the layout the user
actually has, so it is the safer choice.

## Verification plan

1. Run `cargo test --workspace --locked`. The new test fails before the fix and passes after.
2. Manually type `!+?{}:|` into TextEdit on the Mac mini, then `a!b` to check the
   character order.
