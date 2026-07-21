# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build the package
swift build

# Run the deterministic test suite (Apple's Testing framework, not XCTest)
swift test

# Run the opt-in live test (resolves a real public host over the network)
SSRFGUARD_LIVE_TESTS=1 swift test

# Run SwiftLint (strict mode, as CI does)
swiftlint --strict

# Build in release mode
swift build -c release
```

## Architecture

SSRFGuard classifies whether an IP address is a safe outbound (egress) target or one that names a
private, loopback, link-local, or otherwise reserved destination. It is a pure classifier over
value types: no networking, no third-party runtime dependencies, and the same behavior on Apple
platforms and Linux behind one resolver seam.

The classifier is two layers. A fixed canonicalization step unwraps IPv4-mapped, NAT64, and
IPv4-compatible IPv6 forms to their embedded IPv4 and re-checks them, and fails closed on a
malformed (non-sixteen-byte) IPv6 value; this anti-bypass core is not configurable. A configurable
`EgressPolicy` holds the blocked `[CIDR]` set, and `EgressPolicy.strict` is the default, pinning the
IANA special-purpose, private, and reserved ranges for both address families.

### Core Components

- **EgressClassifier**: the entry point. `classify(_:)` returns a `Classification` verdict, and
  `isAllowed(_:)` is the yes/no form. It canonicalizes, then checks the address against the policy.
- **Classification / BlockReason**: the typed verdict, `.allowed`, or `.blocked(.matchedRange)` /
  `.blocked(.malformed)`.
- **EgressPolicy**: the blocked-range set. `.strict` default plus `adding(_:)` to layer extra CIDRs.
- **CIDR / ResolvedAddress**: the value types. `CIDR` is a family-strict network; `ResolvedAddress`
  is a parsed IPv4/IPv6 literal, with `denotesIPLiteral(host:)` to catch legacy numeric spellings.
- **AddressResolving / SystemAddressResolver**: the DNS seam and its bundled default, which runs
  `getaddrinfo` on a Dispatch worker so a stalled lookup never pins the cooperative pool.

### Not a DNS-rebinding defense

This is a classifier, not a connect-time guard. Classifying a hostname's address and then connecting
by that hostname lets a resolver return a public address to the check and a private one to the
connection. Callers must resolve once, classify the exact address, and connect to that pinned
address.

### Platform Requirements

- iOS 16.0+, macOS 13.0+, tvOS 16.0+, watchOS 9.0+, visionOS 1.0+, and Linux
- Swift 6.0+ (strict concurrency)
- No third-party runtime dependencies (`swift-docc-plugin` is a build-tool plugin for docs only)

### Testing

Tests use Apple's `Testing` framework in two tiers:

- **Deterministic (default):** the classifier, policy, and value types over pinned fixtures, plus
  the resolver seam driven by a scripted `AddressResolving`. These run anywhere the package builds
  and never touch the network.
- **Live (opt-in via `SSRFGUARD_LIVE_TESTS=1`):** resolves a real public host and asserts it
  classifies as allowed.

Shared test doubles live in `TestHelpers.swift`.

## Code Style

SwiftLint enforced with `--strict` (no swift-format). Key rules:

- 2-space indentation; line length 120 warning / 150 error
- Opt-in rules include `force_unwrapping`, `implicit_return`, `conditional_returns_on_newline`,
  `trailing_closure`; no trailing commas in collection literals
- Tests follow Given-When-Then (`// given` / `// when` / `// then`)
