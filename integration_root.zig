//! Repo-root view for the integration test binary.
//!
//! Zig's module system requires that every `@import()` path resolve
//! within the current module's source tree. The integration test at
//! `tests/integration_ipc_roundtrip.zig` needs to reach into `engine/`
//! files — which would be rejected with "import of file outside module
//! path" if the module root was `tests/`.
//!
//! The fix: set this file (at the repository root) as the test
//! module's root, then re-export the real test file so its
//! `test "..."` blocks are discovered and its `@import("engine/...")`
//! paths resolve within the repo-root subtree.
//!
//! This shim lives at repo root alongside `engine/`, `tests/`, and
//! `shared/`; it has no test code of its own.

test {
    _ = @import("tests/integration_ipc_roundtrip.zig");
}
