# Code Review: CLI Feature (exec/env subcommands)

## Summary

| # | Issue | File | Severity | Status |
|---|-------|------|----------|--------|
| 1 | Scanner error not checked after Scan() | confirm.go:33 | Medium | Fixed |
| 2 | Partial scope mutation on parse error | scope.go:26 | Medium | Fixed |
| 3 | No early service name validation before confirm | exec.go, env.go | Medium | Fixed |
| 4 | No early TTL bounds check before confirm | exec.go, env.go | Medium | Fixed |
| 5 | execChild uses context.Background() instead of caller ctx | exec.go:112 | Low | Fixed |
| 6 | No child process timeout in execChild | exec.go:99-125 | Low | Won't fix |
| 7 | os.Exit in execChild bypasses defers | exec.go:121 | Low | Won't fix |
| 8 | Uncaptured fs.String("ttl") pointer | env.go:41, exec.go:30 | Low | Fixed |
| 9 | Package alias timebound for aws package | cmd/cli/*.go | Low | Won't fix |
| 10 | No integration tests for CLI commands | cmd/cli/ | Low | Won't fix |

---

## Details

### 1. Scanner error not checked after Scan()

**File:** `cmd/cli/confirm.go:33-36`

`bufio.Scanner.Scan()` returns false on both EOF and read error. The code reports "no input received" in both cases, masking actual I/O errors from the user.

```go
// current
if !scanner.Scan() {
    return fmt.Errorf("no input received")
}

// fix
if !scanner.Scan() {
    if err := scanner.Err(); err != nil {
        return fmt.Errorf("reading input: %w", err)
    }
    return fmt.Errorf("no input received")
}
```

---

### 2. Partial scope mutation on parse error

**File:** `cmd/cli/scope.go:26-36`

When parsing `-s s3:ro,bad:level`, the first valid scope (s3:ro) is appended to `f.scopes` before the error is returned for the second. This leaves the flag in a partially mutated state. Parsing should be all-or-nothing.

```go
// fix: parse into a local slice, only append on full success
func (f *scopeFlag) Set(val string) error {
    var parsed []timebound.ServiceScope
    for _, item := range strings.Split(val, ",") {
        // ... parse into parsed slice ...
    }
    f.scopes = append(f.scopes, parsed...)
    return nil
}
```

---

### 3. No early service name validation before confirm

**File:** `cmd/cli/exec.go`, `cmd/cli/env.go`

Service names are not validated until `broker.GrantAccess()` is called, which happens after the user has already reviewed the summary table and confirmed. A typo like `s3x:ro` passes through scope parsing, appears in the summary, gets confirmed, and only then fails.

Fix: call `timebound.ValidateServices()` on the parsed scope service names before rendering the summary.

---

### 4. No early TTL bounds check before confirm

**File:** `cmd/cli/exec.go`, `cmd/cli/env.go`

`time.ParseDuration()` accepts any valid Go duration including values outside the broker's 15m-12h range. A user can pass `-t 1s` or `-t 999h`, see the summary, confirm, and only then get a validation error from the broker.

Fix: check TTL against the broker's min/max bounds before rendering the summary.

---

### 5. execChild uses context.Background() instead of caller ctx

**File:** `cmd/cli/exec.go:112`

`RunExec` creates a `context.Background()` at line 67, but `execChild` creates a second one at line 112 instead of receiving and using the caller's context. If signal handling or cancellation is added later, the child process won't respect it.

Fix: pass the context from `RunExec` into `execChild` and use it in `exec.CommandContext`.

---

### 6. No child process timeout in execChild (Won't fix)

**File:** `cmd/cli/exec.go:99-125`

The child process runs without a timeout. If it hangs, credentials remain active for their full TTL.

Won't fix: the user controls the child command. Adding a forced timeout would break long-running scripts like deployments. The credential TTL is the actual time bound.

---

### 7. os.Exit in execChild bypasses defers (Won't fix)

**File:** `cmd/cli/exec.go:121`

`os.Exit(exitErr.ExitCode())` is called directly, bypassing any deferred cleanup in the call stack.

Won't fix: this is intentional. The CLI must forward the child's exit code to the calling shell. There are no defers in the exec path that require cleanup.

---

### 8. Uncaptured fs.String("ttl") pointer (Fixed)

**File:** `cmd/cli/env.go:41`, `cmd/cli/exec.go:30`

`fs.String("ttl", ...)` registers the flag but the returned pointer is discarded. The value is retrieved later by walking the FlagSet in `resolveTTLFlag()`. This works but is unusual.

Fixed: replaced with `fs.StringVar` pointing both `-t` and `--ttl` at the same variable (matching the existing `fs.Var` pattern used for scope flags). Deleted `resolveTTLFlag` entirely.

---

### 9. Package alias timebound for aws package (Won't fix)

**File:** `cmd/cli/*.go`

The package at `timebound/aws` is imported as `timebound` throughout the CLI. The actual Go package name is `timebound` (declared in the source files), so the alias is correct, just potentially confusing given the directory name `aws`.

Won't fix: this is the existing convention across the entire codebase.

---

### 10. No integration tests for CLI commands (Won't fix)

**File:** `cmd/cli/`

All CLI tests are unit tests. There are no end-to-end tests that mock the broker and exercise the full flag parsing, confirmation, credential acquisition, and output flow.

Won't fix for now: unit tests cover the individual components well. Integration tests are a good follow-up but not a bug.
