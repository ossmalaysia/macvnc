// DOM KeyboardEvent -> X11 keysym.
//
// On macOS the X11 modifier names do NOT mean what they say:
//   Meta_L  0xffe7 / Meta_R  0xffe8  -> Option
//   Super_L 0xffeb / Super_R 0xffec  -> Command
//   Control_L 0xffe3 / Control_R 0xffe4 -> Control
// Everything below follows that, not the label.

export const PROFILE_CTRL_AS_CMD = 'ctrl-as-cmd';
export const PROFILE_NATIVE = 'native';

export const MODIFIER_KEYSYMS = [
  0xffe1, // Shift_L
  0xffe2, // Shift_R
  0xffe3, // Control_L
  0xffe4, // Control_R
  0xffe5, // Caps_Lock
  0xffe6, // Shift_Lock
  0xffe7, // Meta_L   -> Option on macOS
  0xffe8, // Meta_R   -> Option on macOS
  0xffe9, // Alt_L
  0xffea, // Alt_R
  0xffeb, // Super_L  -> Command on macOS
  0xffec, // Super_R  -> Command on macOS
];

// Physical-key -> keysym, per profile. Left/right must stay distinguishable,
// so these are keyed by `code`, never by `key`.
const MODIFIERS_BY_CODE = {
  // Default. The local Ctrl becomes Command so muscle memory (Ctrl+C = copy)
  // lands on the Mac shortcut; the RIGHT Ctrl stays a real Control so Terminal
  // still gets ^C / ^A / ^E.
  [PROFILE_CTRL_AS_CMD]: {
    ControlLeft: 0xffeb,
    ControlRight: 0xffe4,
    AltLeft: 0xffe7,
    AltRight: 0xffe8,
    MetaLeft: 0xffe3,
    MetaRight: 0xffe3,
    OSLeft: 0xffe3,
    OSRight: 0xffe3,
    ShiftLeft: 0xffe1,
    ShiftRight: 0xffe2,
    CapsLock: 0xffe5,
  },
  // Label-faithful: every key sends what its X11 name says.
  [PROFILE_NATIVE]: {
    ControlLeft: 0xffe3,
    ControlRight: 0xffe4,
    AltLeft: 0xffe7,
    AltRight: 0xffe8,
    MetaLeft: 0xffeb,
    MetaRight: 0xffec,
    OSLeft: 0xffeb,
    OSRight: 0xffec,
    ShiftLeft: 0xffe1,
    ShiftRight: 0xffe2,
    CapsLock: 0xffe5,
  },
};

// Fallback when `code` is absent or unrecognised (synthetic events, some IMEs).
// Assumes the left-hand key.
const MODIFIERS_BY_KEY = {
  [PROFILE_CTRL_AS_CMD]: {
    Control: 0xffeb,
    Alt: 0xffe7,
    AltGraph: 0xffe8,
    Meta: 0xffe3,
    OS: 0xffe3,
    Shift: 0xffe1,
    CapsLock: 0xffe5,
  },
  [PROFILE_NATIVE]: {
    Control: 0xffe3,
    Alt: 0xffe7,
    AltGraph: 0xffe8,
    Meta: 0xffeb,
    OS: 0xffeb,
    Shift: 0xffe1,
    CapsLock: 0xffe5,
  },
};

const NAMED_KEYS = {
  Enter: 0xff0d,
  Tab: 0xff09,
  Backspace: 0xff08,
  Escape: 0xff1b,
  Delete: 0xffff,
  Home: 0xff50,
  End: 0xff57,
  PageUp: 0xff55,
  PageDown: 0xff56,
  Insert: 0xff63,
  ArrowLeft: 0xff51,
  ArrowUp: 0xff52,
  ArrowRight: 0xff53,
  ArrowDown: 0xff54,
  F1: 0xffbe,
  F2: 0xffbf,
  F3: 0xffc0,
  F4: 0xffc1,
  F5: 0xffc2,
  F6: 0xffc3,
  F7: 0xffc4,
  F8: 0xffc5,
  F9: 0xffc6,
  F10: 0xffc7,
  F11: 0xffc8,
  F12: 0xffc9,
};

function resolveProfile(profile) {
  return profile === PROFILE_NATIVE ? PROFILE_NATIVE : PROFILE_CTRL_AS_CMD;
}

/**
 * @param {string} key   KeyboardEvent.key
 * @param {string} code  KeyboardEvent.code
 * @param {string} [profile]
 * @returns {number|null} X11 keysym, or null if unmappable
 */
export function keysymForDomKey(key, code, profile) {
  const p = resolveProfile(profile);

  if (typeof code === 'string' && code !== '') {
    const mod = MODIFIERS_BY_CODE[p][code];
    if (mod !== undefined) return mod;
  }

  if (typeof key !== 'string' || key === '') return null;

  const modByKey = MODIFIERS_BY_KEY[p][key];
  if (modByKey !== undefined) return modByKey;

  const named = NAMED_KEYS[key];
  if (named !== undefined) return named;

  // Printable. Array.from so an astral character counts as one.
  const chars = Array.from(key);
  if (chars.length !== 1) return null;

  const cp = chars[0].codePointAt(0);
  if (cp >= 0x20 && cp <= 0xff) return cp;
  return 0x01000000 + cp;
}
