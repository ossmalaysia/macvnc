# Validation: 2026-09-05

## Changes checked

- Saved profiles no longer auto-connect with a missing/decryption-failed password.
- Forget clears both the current and pre-rename profile locations.
- Failed secure storage leaves existing credentials intact and reports an error.
- Authentication errors are recognized and survive a following close notification.
- Terminal protocol/authentication failures close their transport.
- DesktopSize changes update the visible canvas backing dimensions.
- Invalid port suffixes and failed IPC results are shown as connection errors.

## Evidence

- `npm test`: 114 passed, including 10 new credential/renderer regressions.
- `node --check src/main/index.js` and `node --check src/renderer/app.js`: passed.
- `git diff --check`: passed.
- Browser tool, localhost fixture using the production renderer and decode worker:
  required-host validation, invalid port rejection, RGB565 red/green/blue/white
  quadrant rendering, resize from 320x180 to 640x360 (canvas dimensions verified),
  disconnect, and synthetic authentication error display passed. Browser error
  and warning logs were empty.
- Live Electron protocol check used the app's existing safeStorage-encrypted
  profile: authenticated successfully and decoded one complete 1920x1080
  framebuffer update. No input/clipboard commands were sent, no credentials or
  desktop contents were recorded, and the connection was closed after the update.

## Limits

Browser checks used a synthetic MessagePort transport because a normal browser
has no Electron preload/TCP bridge. The live check exercised credential loading,
RFB authentication, framing and decoding in Electron, separately from the browser
UI checks. This is not a full native-window end-to-end test or a sustained
performance test. Experimental HP/HEVC compositing remains incomplete and was
not enabled. Packaged installers were not rebuilt.
