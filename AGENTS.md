# Current implementation: native Rust HP rewrite

The user explicitly authorized a full Rust application with HP as its primary
mode and parallel agent implementation. The Rust workspace is the current target;
read `rust/AGENTS.md` for its architecture, invariants and validation commands.
`README.md` describes native builds. The Electron notes below are retained only
for the JavaScript reference tree; their HP opt-in restriction does not prevent
the explicitly authorized Rust HP implementation. Experimental status must remain
visible until live screen correctness and sustained playback are verified.

# Repository guidance

macvnc is an Electron desktop client for Apple's macOS Screen Sharing (RFB
3.889, security type 30). Read `README.md`, `SECURITY.md`, and
`docs/CONTRACTS.md` before changing protocol behavior. HP mode in `src/rfb-hp/`
is experimental and has unresolved tile/compositing problems; keep it opt-in.

## Architecture

- `src/main/`: TCP transport, Electron lifecycle, IPC, OS-encrypted credentials.
- `src/preload/index.cjs`: explicit CommonJS context bridge.
- `src/renderer/`: form/input handling and visible canvas; its worker decodes
  compressed rectangles and transfers ImageBitmaps back for painting.
- `src/rfb/`: portable ESM protocol, crypto, decoders, key mapping and metrics.
- `src/vendor/pako.esm.mjs`: browser inflater; preserve its streaming behavior.
- `test/`: Node's built-in test runner and synthetic wire/renderer fixtures.

## Invariants

- Keep `src/rfb/` usable in Node and browser workers: no Electron, Node imports,
  Buffer, filesystem, networking or timers. Inject randomness into authentication.
- Read encoding IDs as signed integers. Preserve mark/rewind semantics on partial
  TCP input and test framing with single-byte chunks.
- Maintain exactly one outstanding framebuffer request, rearmed on updateDone.
- Inflate streams persist across rectangles but reset for each new connection.
- The production format is RGB565; do not advertise ZRLE until it supports that
  format. Ship compressed rectangles across IPC, not full decoded framebuffers.
- Keep credentials, key material and real desktop captures out of logs/git.
  Use safeStorage; never auto-retry authentication failures or auto-connect with
  an unavailable saved password. Keep the default host blank.

## Validation

- `npm test` runs offline tests; add meaningful regression fixtures for fixes.
- `npm start` launches Electron; `npm run dist:win` packages Windows builds.
- Use browser tooling to validate renderer states and worker rendering with
  synthetic data. A regular browser lacks the Electron preload/TCP bridge;
  distinguish browser fixture checks from a real Electron connection.
- Live tests require the user's authorization and configured credentials. Read
  only the app's saved profile, make no automatic rejected-password retries,
  and report results without passwords, key material or desktop contents.
- Do not commit generated `dist/`, temporary validation artifacts or credentials.
