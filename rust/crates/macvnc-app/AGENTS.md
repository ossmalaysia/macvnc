# Native application

This crate is a native eframe/egui desktop application. Keep JavaScript, Electron,
webviews and subprocess-based crypto out of the production runtime.

- `backend.rs` owns the connection thread. Do not block the egui update thread.
- Repaint on arrival and consume only the latest framebuffer. Do not accumulate
  decoded frames in an unbounded queue.
- Count uploaded remote frames once when drawn, over a rolling one-second window;
  idle repaints do not increment the FPS counter. This measures UI submissions,
  not hardware scanout or decode throughput.
- Label network latency as RTT and distinguish it from input-to-screen delay.
  Sample the existing connection off the UI thread, clear it across sessions,
  and show unavailable rather than inventing a value when unsupported.
- Never derive Debug for password-bearing options or profiles. Passwords must not
  enter egui persistence, logs or command-line arguments.
- Windows native credentials use DPAPI. Electron import is scoped to this app's
  saved connection and Local State. Never enumerate other application secrets.
- A corrupt current profile must not fall back to an older account. A missing or
  undecryptable password disables auto-connect. No rejected-password retries.
- `--smoke-ui` renders synthetic data, does not load a saved profile, never
  connects, and closes itself. Native UI validation is separate from browser tests.
- Release all held keys/buttons on focus loss and disconnect. Key-up must use the
  keysym actually sent on key-down. egui's modifier events aggregate left/right
  keys; right-Control passthrough needs raw native input before parity is claimed.
- `Forget saved connection` writes an empty native profile so old Electron login
  data cannot be silently imported again. Electron files remain read-only.
