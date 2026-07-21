/// The set of IP ranges an ``EgressClassifier`` refuses. An address that matches any range is
/// blocked; anything else is allowed.
public struct EgressPolicy: Sendable, Equatable {
  public let blockedRanges: [CIDR]

  public init(blockedRanges: [CIDR]) {
    self.blockedRanges = blockedRanges
  }

  /// Returns a policy that blocks everything this one does plus `ranges` — e.g. an organization's
  /// internal CIDRs layered on top of ``strict``.
  public func adding(_ ranges: [CIDR]) -> EgressPolicy {
    EgressPolicy(blockedRanges: blockedRanges + ranges)
  }
}

// MARK: - Strict Default

extension EgressPolicy {
  /// The strict default: the IANA special-purpose, private, and reserved ranges for both address
  /// families — the deny-list for an SSRF check on an outbound target.
  public static let strict = EgressPolicy(blockedRanges: strictRanges)

  private static let strictRanges: [CIDR] = [
    // IPv4
    "0.0.0.0/8",  // "this host on this network" and the unspecified address
    "10.0.0.0/8",  // RFC 1918 private
    "100.64.0.0/10",  // RFC 6598 CGNAT
    "127.0.0.0/8",  // loopback
    "169.254.0.0/16",  // link-local (includes the 169.254.169.254 cloud-metadata endpoint)
    "172.16.0.0/12",  // RFC 1918 private
    "192.0.0.0/24",  // IETF protocol assignments
    "192.0.2.0/24",  // TEST-NET-1
    "192.168.0.0/16",  // RFC 1918 private
    "198.18.0.0/15",  // RFC 2544 benchmarking
    "198.51.100.0/24",  // TEST-NET-2
    "203.0.113.0/24",  // TEST-NET-3
    "224.0.0.0/4",  // multicast
    "240.0.0.0/4",  // reserved (includes the 255.255.255.255 broadcast address)
    // IPv6
    "fe80::/10",  // link-local
    "fc00::/7",  // unique local (ULA)
    "ff00::/8",  // multicast
    "2001:db8::/32",  // documentation
  ].map(EgressPolicy.parseOrTrap)

  private static func parseOrTrap(_ text: String) -> CIDR {
    guard let range = CIDR.parse(text) else {
      preconditionFailure("built-in CIDR literal must parse: \(text)")
    }
    return range
  }
}
