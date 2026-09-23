# Component tests

Each `*_tests.zig` file is a focused test root registered in `build.zig` with a
named step, filter and maintained CI lane. Direct internal engine imports go
through the test-only `engine_test` module (`engine/test_api.zig`), which keeps
source files in one Zig module and satisfies the module graph guard. Client
format tests use a dedicated test-only module. Peer test fixtures may use
relative imports within this directory.

`store/` holds the 47 record-store contract tests formerly inline in
`engine/store/store.zig`. Foundation, detection, retry and consumer test roots
import its suite so their existing filters continue to select the same cases. Keep
failure-injection and crash/reopen cases tied to distinct durability risks;
review overlap before removing assertions.
