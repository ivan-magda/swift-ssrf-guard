import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#elseif canImport(Musl)
  import Musl
#endif

/// An IP address in a form the classifier can check: `.ipv4` holds the 32-bit value in host byte
/// order, `.ipv6` the sixteen raw bytes in network order.
public enum ResolvedAddress: Sendable, Equatable {
  case ipv4(UInt32)
  case ipv6([UInt8])

  /// Parses a textual IPv4/IPv6 literal via `inet_pton`; nil for anything else.
  public static func parse(_ text: String) -> ResolvedAddress? {
    var v4Address = in_addr()
    if inet_pton(AF_INET, text, &v4Address) == 1 {
      return .ipv4(UInt32(bigEndian: v4Address.s_addr))
    }

    var v6Address = in6_addr()
    if inet_pton(AF_INET6, text, &v6Address) == 1 {
      let bytes = withUnsafeBytes(of: &v6Address) { raw in Array(raw) }
      return .ipv6(bytes)
    }

    return nil
  }

  /// Whether `host` is an IP address literal rather than a DNS name — including the legacy numeric
  /// IPv4 spellings (`inet_aton`: a bare 32-bit integer, `0x…` hex, octal, and short-dotted forms)
  /// that strict ``parse(_:)``/`inet_pton` reject yet `getaddrinfo` still resolves locally without
  /// a DNS query. Use it to decide whether a host needs resolving at all, and so an obfuscated
  /// literal such as `0x7f000001` (127.0.0.1) is never mistaken for a name that escapes a
  /// literal check.
  public static func denotesIPLiteral(host: String) -> Bool {
    if parse(host) != nil {
      return true
    }

    var v4Address = in_addr()
    return host.withCString { pointer in
      inet_aton(pointer, &v4Address) != 0
    }
  }
}

extension ResolvedAddress: CustomStringConvertible {
  /// The canonical textual form (dotted-quad v4 / RFC 5952 compressed v6) via `inet_ntop`,
  /// for diagnostics such as a refusal message.
  public var description: String {
    switch self {
    case .ipv4(let value):
      var raw = in_addr(s_addr: value.bigEndian)
      var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))

      guard inet_ntop(AF_INET, &raw, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
        return "invalid-ipv4"
      }

      return buffer.withUnsafeBufferPointer { pointer in
        guard let base = pointer.baseAddress else {
          return "invalid-ipv4"
        }
        return String(cString: base)
      }
    case .ipv6(let bytes):
      guard bytes.count == 16 else {
        return "invalid-ipv6"
      }

      var raw = in6_addr()
      withUnsafeMutableBytes(of: &raw) { destination in
        destination.copyBytes(from: bytes)
      }

      var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
      guard inet_ntop(AF_INET6, &raw, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
        return "invalid-ipv6"
      }

      return buffer.withUnsafeBufferPointer { pointer in
        guard let base = pointer.baseAddress else {
          return "invalid-ipv6"
        }
        return String(cString: base)
      }
    }
  }
}
