import Foundation

/// Classifies whether an IP address is a safe outbound (egress) target — publicly routable — or one
/// that should be refused because it names a private, loopback, link-local, or otherwise reserved
/// destination. The refused set is an ``EgressPolicy``; the default is ``EgressPolicy/strict``.
///
/// IPv4-mapped, NAT64 (`64:ff9b::/96`), and IPv4-compatible IPv6 forms are unwrapped to their
/// embedded IPv4 and re-checked, so a private destination cannot be reached through an equivalent
/// v6 spelling. A malformed IPv6 value (not sixteen bytes) is refused.
///
/// > Important: This is a *classifier*, not a defense against DNS rebinding. Classifying a
/// > hostname's address and then connecting by that hostname lets a resolver hand a public address
/// > to the check and a private one to the connection. Resolve once, classify the exact address,
/// > and connect to that pinned address.
public struct EgressClassifier: Sendable {
  public let policy: EgressPolicy

  public init(policy: EgressPolicy = .strict) {
    self.policy = policy
  }

  /// Classifies `address`, reporting why it was refused when it is not allowed.
  public func classify(_ address: ResolvedAddress) -> Classification {
    let canonical: ResolvedAddress
    switch address {
    case .ipv4:
      canonical = address
    case .ipv6(let bytes):
      guard bytes.count == 16 else {
        return .blocked(.malformed)
      }
      if let embedded = Self.embeddedIPv4(bytes) {
        canonical = .ipv4(embedded)
      } else {
        canonical = address
      }
    }

    for range in policy.blockedRanges where range.contains(canonical) {
      return .blocked(.matchedRange(range))
    }

    return .allowed
  }

  /// Whether `address` is allowed — the yes/no form of ``classify(_:)``.
  public func isAllowed(_ address: ResolvedAddress) -> Bool {
    classify(address) == .allowed
  }
}

// MARK: - IPv6 Unwrapping

extension EgressClassifier {
  /// The IPv4 address embedded in an IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`), or
  /// IPv4-compatible (`::/96`, deprecated) IPv6 address; nil when `bytes` carries none of those
  /// forms. `bytes` must be sixteen elements — the caller checks first.
  private static func embeddedIPv4(_ bytes: [UInt8]) -> UInt32? {
    let isMapped =
      bytes[0...9].allSatisfy { $0 == 0 }
      && bytes[10] == 0xFF
      && bytes[11] == 0xFF

    let isNAT64 =
      bytes[0] == 0x00
      && bytes[1] == 0x64
      && bytes[2] == 0xFF
      && bytes[3] == 0x9B
      && bytes[4...11].allSatisfy { $0 == 0 }

    let isCompatible = bytes[0...11].allSatisfy { $0 == 0 }

    guard isMapped || isNAT64 || isCompatible else {
      return nil
    }

    return (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16)
      | (UInt32(bytes[14]) << 8)
      | UInt32(bytes[15])
  }
}
