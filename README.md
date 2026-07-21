# SSRFGuard

[![CI](https://github.com/ivan-magda/swift-ssrf-guard/actions/workflows/swift.yml/badge.svg)](https://github.com/ivan-magda/swift-ssrf-guard/actions/workflows/swift.yml)
[![Swift 6.0](https://img.shields.io/badge/Swift-6.0-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/platforms-iOS%20%7C%20macOS%20%7C%20tvOS%20%7C%20watchOS%20%7C%20visionOS%20%7C%20Linux-blue.svg)](https://swift.org)
[![SPM Compatible](https://img.shields.io/badge/SPM-compatible-brightgreen.svg)](https://swift.org/package-manager)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Classify whether an IP address is a safe outbound target or one that points back into a private
network. SSRFGuard refuses private, loopback, link-local, carrier-grade NAT, and other reserved
ranges for both IPv4 and IPv6. It unwraps IPv4-mapped and NAT64 addresses so an equivalent IPv6
spelling cannot slip a private target past the check, and it fails closed on malformed input. It is
pure Swift with no third-party runtime dependencies, and it runs the same on Apple platforms and
Linux.

> [!IMPORTANT]
> SSRFGuard is a classifier, not a defense against DNS rebinding. Classifying a hostname's address
> and then connecting by that hostname lets a resolver hand a public address to the check and a
> private one to the connection. Resolve once, classify the exact address, and connect to that
> pinned address.

```swift
import SSRFGuard

let classifier = EgressClassifier() // strict defaults

if let address = ResolvedAddress.parse("169.254.169.254") {
  classifier.isAllowed(address) // false: the link-local cloud-metadata endpoint
}
```

## Table of Contents

- [Background](#background)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Background

Server-Side Request Forgery (SSRF) happens when a server fetches a URL on someone else's behalf and
the attacker steers that fetch at an internal target: the loopback interface, a private
subnet, or a cloud metadata endpoint such as `169.254.169.254`. Any feature that turns user input
into an outbound connection forces you to decide whether the resolved destination is a public address
or an internal one.

SSRFGuard grew out of a personal assistant daemon that fetches URLs for its owner and must refuse
anything that reaches back inside the host. It is small and honest about its scope: it classifies
addresses. It does not open sockets, follow redirects, or pin connections, and
it is not a rebinding defense on its own. Pair it with connection-time pinning for that (see the
note above).

SSRFGuard handles the cases that are easy to get wrong: IPv4-mapped, NAT64, and IPv4-compatible IPv6
forms are unwrapped to the embedded IPv4 and re-checked, the legacy numeric IPv4 spellings that
`inet_pton` rejects but `getaddrinfo` still resolves are recognized as literals, and a malformed
address is refused rather than allowed.

## Features

- **Strict by default.** `EgressPolicy.strict` blocks private, loopback, link-local, CGNAT,
  benchmarking, documentation, multicast, and reserved ranges for IPv4 and IPv6.
- **Anti-bypass canonicalization.** IPv4-mapped, NAT64 (`64:ff9b::/96`), and IPv4-compatible IPv6
  addresses are unwrapped to their embedded IPv4 and re-checked, so a v6 spelling cannot smuggle a
  private target through.
- **Fails closed.** A malformed address (an IPv6 value that is not sixteen bytes) is refused, never
  allowed.
- **Configurable policy.** Layer your own CIDRs on top of the strict set, or supply your own list.
- **Typed verdicts.** A `Classification` tells you why an address was refused: which range matched,
  or that the input was malformed.
- **Off-pool resolver.** The bundled resolver runs `getaddrinfo` on a Dispatch worker, so a stalled
  DNS lookup never pins one of the Swift concurrency pool's fixed threads.
- **No third-party runtime dependencies.** Pure libc, Dispatch, and Foundation. Builds and tests
  green on Linux.

## Requirements

- iOS 16.0+, macOS 13.0+, tvOS 16.0+, watchOS 9.0+, visionOS 1.0+, or Linux
- Swift 6.0+ / Xcode 16+

## Installation

### Xcode

In Xcode, open **File -> Add Package Dependencies…**, enter the repository URL, and add the
`SSRFGuard` library to your target:

```
https://github.com/ivan-magda/swift-ssrf-guard
```

### Package.swift

Add the package to your dependencies:

```swift
dependencies: [
  .package(url: "https://github.com/ivan-magda/swift-ssrf-guard", from: "1.0.0")
]
```

Then add `SSRFGuard` to your target:

```swift
.target(
  name: "YourTarget",
  dependencies: [
    .product(name: "SSRFGuard", package: "swift-ssrf-guard")
  ]
)
```

## Usage

### Classify an address

`EgressClassifier` uses `EgressPolicy.strict` by default. `classify(_:)` returns a typed verdict;
`isAllowed(_:)` is the yes/no form.

```swift
import SSRFGuard

let classifier = EgressClassifier()

guard let address = ResolvedAddress.parse("10.0.0.1") else { return }

switch classifier.classify(address) {
case .allowed:
  connect(to: address)
case .blocked(.matchedRange(let range)):
  log("refused: \(address) is in \(range)") // refused: 10.0.0.1 is in 10.0.0.0/8
case .blocked(.malformed):
  log("refused: malformed address")
}
```

### Resolve a host, then classify

Resolve the host to concrete addresses, classify each one, and connect only to an address you
classified. Do not connect back by hostname: that reintroduces the rebinding gap described at the
top.

```swift
let resolver = SystemAddressResolver()
let classifier = EgressClassifier()

let addresses = try await resolver.resolve(host: "example.com")
for address in addresses where classifier.isAllowed(address) {
  connect(to: address) // pin the socket to this exact address
}
```

### Customize the blocked ranges

Layer extra ranges on top of the strict set, or build a policy from scratch.

```swift
if let corporate = CIDR.parse("203.0.113.0/24") {
  let classifier = EgressClassifier(policy: .strict.adding([corporate]))
}

let openPolicy = EgressPolicy(blockedRanges: []) // blocks nothing except malformed input
```

### Test without the network

Inject a scripted `AddressResolving` to drive tests deterministically.

```swift
struct ScriptedResolver: AddressResolving {
  let table: [String: [ResolvedAddress]]
  func resolve(host: String) async throws -> [ResolvedAddress] {
    guard let addresses = table[host] else {
      throw AddressResolutionError.unresolvable(host: host)
    }
    return addresses
  }
}
```

## How It Works

1. **Canonicalize.** For an IPv6 address, unwrap an IPv4-mapped, NAT64, or IPv4-compatible form to
   the embedded IPv4. A value that is not sixteen bytes is refused as malformed.
2. **Check the policy.** Test the canonical address against each `CIDR` in the policy. The first
   range that contains it wins, and the classifier reports that range back.
3. **Return a verdict.** `.allowed` when no range matched, otherwise `.blocked` with the reason.

Matching is strict per address family: an IPv4-mapped IPv6 form never matches an IPv4 block on its
own, which is why the canonicalization step unwraps it first. That ordering stops
`64:ff9b::7f00:1` from reaching `127.0.0.1` on a NAT64 network.

## Project Structure

```
Sources/SSRFGuard/
├── Address/       # ResolvedAddress and CIDR value types
├── Classifier/    # EgressClassifier, EgressPolicy, and the Classification verdict
└── Resolver/      # the AddressResolving seam and the getaddrinfo default
```

## Contributing

Issues and pull requests are welcome.

```bash
swift build
swift test                    # deterministic suite
SSRFGUARD_LIVE_TESTS=1 swift test   # opt-in live resolution
swiftlint --strict
```

Tests follow Given-When-Then.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
