# Workspace Structure

USG RADIUS uses a Cargo workspace to organize code into modular, reusable crates.

## Directory Structure

```
usg-radius/
├── Cargo.toml                      # Workspace root
├── crates/
│   ├── radius-proto/               # Protocol implementation
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── packet/             # Packet encoding/decoding
│   │       ├── attributes/         # Attribute handling
│   │       └── auth.rs             # Cryptographic operations
│   │
│   └── radius-server/              # Server implementation
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── main.rs             # Binary entry point
│       │   ├── server.rs           # Server core
│       │   └── config.rs           # Configuration
│       └── examples/
│           └── simple_client.rs    # Example client
│
├── docs/                           # Zensical documentation
├── target/                         # Build artifacts
├── README.md                       # Project README
├── ROADMAP.md                      # Development roadmap
├── RFC-COMPLIANCE.md               # RFC compliance analysis
└── CONTRIBUTING.md                 # Contribution guidelines
```

## Workspace Benefits

### Modularity

- **radius-proto**: Can be used standalone for clients, proxies, or custom servers
- **radius-server**: Builds on radius-proto for a complete server solution
- Clear separation of concerns

### Code Reuse

- Shared dependencies across crates
- Consistent versioning
- Reduced duplication

### Development

- Build all crates together: `cargo build --workspace`
- Test all crates: `cargo test --workspace`
- Build specific crate: `cargo build -p radius-proto`

### Future Expansion

Easy to add new crates:

- `radius-client` - Client library
- `radius-proxy` - Proxy server
- `radius-tools` - CLI utilities
- `radius-dict` - Dictionary parser

## Dependency Graph

```
radius-server
    └── radius-proto
        ├── md5
        ├── rand
        └── thiserror
```

## Workspace Configuration

Shared configuration in root `Cargo.toml`:

```toml
[workspace]
members = ["crates/radius-proto", "crates/radius-server"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["..."]
license = "Apache-2.0"

[workspace.dependencies]
# Shared dependencies
tokio = { version = "1", features = ["full"] }
# ...
```

## Building & Testing

### Build Everything

```bash
cargo build --workspace
cargo build --workspace --release
```

### Test Everything

```bash
cargo test --workspace
```

### Build Specific Crate

```bash
cargo build -p radius-proto
cargo build -p radius-server --release
```

### Run Server

```bash
cargo run -p radius-server
# or with custom config
cargo run -p radius-server -- /path/to/config.json
```

### Run Example

```bash
cargo run -p radius-server --example simple_client alice password secret
```

## Documentation

### Generate Docs

```bash
# All crates
cargo doc --workspace --no-deps --open

# Specific crate
cargo doc -p radius-proto --open
```

## Publishing (Future)

When ready to publish to crates.io:

```bash
# Publish protocol library first (no dependencies on other workspace crates)
cd crates/radius-proto
cargo publish

# Then publish server (depends on published radius-proto)
cd ../radius-server
cargo publish
```

## Migration from Monolith

The project was reorganized from a monolithic structure to a workspace in v0.1.0:

**Before**:

```
src/
├── main.rs
├── lib.rs
├── packet/
├── attributes/
├── auth.rs
├── server.rs
└── config.rs
```

**After**:

```
crates/
├── radius-proto/src/
│   ├── packet/
│   ├── attributes/
│   └── auth.rs
└── radius-server/src/
    ├── server.rs
    ├── config.rs
    └── main.rs
```

**Benefits**:

- Clear separation of protocol vs. application logic
- radius-proto can be used by other projects
- Easier to maintain and test
- Better for future expansion

## Development Workflow

### Working on Protocol

```bash
cd crates/radius-proto
cargo watch -x test      # Auto-test on changes
cargo build
```

### Working on Server

```bash
cd crates/radius-server
cargo run                # Run server
cargo test               # Run tests
```

### Working on Both

```bash
# From workspace root
cargo build --workspace
cargo test --workspace
```

## CI/CD Implications

Workspace structure affects CI:

```yaml
# .github/workflows/ci.yml
- name: Build workspace
  run: cargo build --workspace --release

- name: Test workspace
  run: cargo test --workspace

- name: Check each crate
  run: |
    cargo check -p radius-proto
    cargo check -p radius-server
```

## Future Workspace Members

Planned additions to the workspace:

1. **radius-client** (Q2 2025)
   - Client library for testing
   - Interoperability testing

2. **radius-proxy** (Q2 2026)
   - Standalone proxy server
   - Routing and load balancing

3. **radius-tools** (Q3 2026)
   - radtest, radclient, raddebug
   - Administrative utilities

4. **radius-dict** (Q4 2026)
   - Dictionary file parsing
   - Vendor-Specific Attributes

Each new crate will be added to `[workspace.members]` in the root Cargo.toml.
