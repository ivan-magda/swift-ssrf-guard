/// The DNS seam: turns a host into the addresses to classify, and lets a caller inject a scripted
/// resolver in tests. ``SystemAddressResolver`` is the bundled `getaddrinfo`-backed default.
public protocol AddressResolving: Sendable {
  func resolve(host: String) async throws -> [ResolvedAddress]
}

/// Thrown by a resolver when a host yields no usable address.
public enum AddressResolutionError: Error, Sendable, Equatable {
  case unresolvable(host: String)
}
