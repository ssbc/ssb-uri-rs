# ssb-uri-rs

Utilities for recognising and converting Secure Scuttlebutt (SSB) URIs according to the [SSB URI Specification](https://github.com/ssb-ngi-pointer/ssb-uri-spec).

## Example

```rust
use ssb_uri_rs;

let example_uri = "ssb:message/sha256/g3hPVPDEO1Aj_uPl0-J2NlhFB2bbFLIHlty-YuqFZ3w=";

assert!(ssb_uri_rs::is_classic_msg_uri(example_uri)?);

let example_sigil = ssb_uri_rs::msg_uri_to_sigil(example_uri)?;

assert_eq!(example_sigil, "%g3hPVPDEO1Aj/uPl0+J2NlhFB2bbFLIHlty+YuqFZ3w=.sha256");
```

## Documentation

Use `cargo doc` to generate and serve the Rust documentation for this library:

```bash
git clone git@github.com:ssb-ngi-pointer/ssb-uri-rs.git
cd ssb-uri-rs
cargo doc --no-deps --open 
```

## License

LGPL-3.0.
