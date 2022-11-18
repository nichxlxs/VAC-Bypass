# Run tests for vac-bypass-rs (64-bit default). Requires Rust toolchain.
Set-Location $PSScriptRoot
cargo test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
