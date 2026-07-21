/// The result of classifying an address with an ``EgressClassifier``.
public enum Classification: Sendable, Equatable {
  /// The address is publicly routable and matched no blocked range.
  case allowed
  /// The address was refused; the associated ``BlockReason`` says why.
  case blocked(BlockReason)
}

/// Why an ``EgressClassifier`` refused an address.
public enum BlockReason: Sendable, Equatable {
  /// The address — or, for an IPv4-mapped, NAT64, or IPv4-compatible IPv6 form, its embedded
  /// IPv4 — fell inside this blocked range.
  case matchedRange(CIDR)
  /// The IPv6 value was not the required sixteen bytes. The classifier fails closed: malformed
  /// input is refused rather than allowed.
  case malformed
}
