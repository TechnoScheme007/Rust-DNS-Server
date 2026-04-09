# DNS Server

A recursive DNS resolver written in Rust that handles the full resolution chain from root servers to authoritative nameservers.

## Features

- **Full Recursive Resolution** - Queries root servers, follows NS referrals down the delegation chain, resolves the complete hierarchy
- **Record Types** - A, AAAA, CNAME, MX, TXT, SRV, NS, SOA, PTR, DS, DNSKEY, RRSIG, NSEC
- **CNAME Chasing** - Automatically follows CNAME chains to resolve final answers
- **DNS Cache** - LRU cache with proper TTL expiration and automatic eviction
- **Authoritative Zones** - Serve your own zones from a TOML config file
- **DNSSEC Validation** - Signature verification for RSA (SHA-256/512), ECDSA (P-256/P-384), and Ed25519
- **DNS-over-HTTPS (DoH)** - RFC 8484 compliant endpoint supporting GET and POST methods
- **UDP + TCP** - Dual-stack server with automatic TCP fallback for truncated responses
- **Async I/O** - Built on Tokio for high-performance concurrent resolution

## Building

```bash
cargo build --release
```

## Configuration

Copy and edit the sample config:

```bash
cp config/config.toml config/my-config.toml
# edit as needed
```

### config/config.toml

```toml
listen_addr = "127.0.0.1:53"
cache_size = 10000
enable_dnssec = false
zones_file = "config/zones.toml"

[doh]
listen_addr = "127.0.0.1:8443"
# tls_cert = "certs/cert.pem"
# tls_key = "certs/key.pem"
```

### Authoritative Zones (config/zones.toml)

```toml
[[zones]]
name = "example.local"

[zones.soa]
mname = "ns1.example.local"
rname = "admin.example.local"
serial = 2024010101
refresh = 3600
retry = 900
expire = 604800
minimum = 300

[[zones.records]]
name = "@"
type = "A"
ttl = 300
value = "127.0.0.1"

[[zones.records]]
name = "www"
type = "CNAME"
value = "example.local"
```

## Running

```bash
# Run with default config (listens on 127.0.0.1:53)
cargo run --release

# With debug logging
RUST_LOG=debug cargo run --release

# With trace-level logging
RUST_LOG=trace cargo run --release
```

> **Note:** Binding to port 53 requires administrator/root privileges on most systems.

## Testing

Point your machine's DNS resolver at the server and browse normally:

### Windows
```powershell
# Run as Administrator
netsh interface ip set dns "Ethernet" static 127.0.0.1
# To restore:
netsh interface ip set dns "Ethernet" dhcp
```

### Linux
```bash
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### macOS
```bash
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1
# To restore:
sudo networksetup -setdnsservers Wi-Fi empty
```

### Manual Testing with dig/nslookup
```bash
# Query A record
dig @127.0.0.1 google.com A

# Query AAAA record
dig @127.0.0.1 google.com AAAA

# Query MX record
dig @127.0.0.1 gmail.com MX

# Query TXT record
dig @127.0.0.1 google.com TXT

# Query authoritative zone
dig @127.0.0.1 example.local A

# Test with nslookup
nslookup google.com 127.0.0.1
```

### Testing DoH
```bash
# POST request
curl -s -H "content-type: application/dns-message" \
  --data-binary @query.bin \
  http://127.0.0.1:8443/dns-query

# Health check
curl http://127.0.0.1:8443/health
```

## Architecture

```
src/
  main.rs          - Entry point, config loading
  dns/             - DNS protocol implementation
    header.rs      - DNS header parsing/serialization
    question.rs    - Question section
    record.rs      - Resource records
    rdata.rs       - Record data types (A, AAAA, MX, etc.)
    name.rs        - Domain name with compression support
    message.rs     - Complete DNS message
    error.rs       - Error types
  resolver/        - Recursive resolver engine
  cache/           - LRU cache with TTL expiration
  zone/            - Authoritative zone management
  dnssec/          - DNSSEC signature validation
  doh/             - DNS-over-HTTPS server
  server/          - UDP/TCP DNS server
config/
  config.toml      - Server configuration
  zones.toml       - Authoritative zone definitions
```

## License

MIT
