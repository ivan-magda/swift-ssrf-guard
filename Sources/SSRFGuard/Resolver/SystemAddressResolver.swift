import Dispatch
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#elseif canImport(Musl)
  import Musl
#endif

/// The bundled resolver, backed by `getaddrinfo` — the same on macOS and Linux behind the one
/// seam. `getaddrinfo` is a blocking syscall that never observes cancellation, so it runs on a
/// Dispatch worker thread rather than the cooperative pool: after the caller's timeout abandons
/// this task, a stalled resolve must not pin one of the pool's fixed threads for its OS-level retry
/// window (commonly 30 s–2 min against a DNS blackhole).
public struct SystemAddressResolver: AddressResolving {
  public init() {}

  public func resolve(host: String) async throws -> [ResolvedAddress] {
    // A literal IP needs no lookup (and must not hit DNS).
    if let literal = ResolvedAddress.parse(host) {
      return [literal]
    }

    return try await withCheckedThrowingContinuation { continuation in
      DispatchQueue.global(qos: .utility).async {
        continuation.resume(with: Result { try Self.blockingResolve(host: host) })
      }
    }
  }

  private static func blockingResolve(host: String) throws -> [ResolvedAddress] {
    var hints = addrinfo()
    #if canImport(Glibc)
      // Glibc types SOCK_STREAM as the `__socket_type` enum; ai_socktype is a plain CInt.
      hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
    #elseif canImport(Musl)
      // Musl types SOCK_STREAM as a plain Int32 macro.
      hints.ai_socktype = Int32(SOCK_STREAM)
    #else
      hints.ai_socktype = SOCK_STREAM  // Darwin already types SOCK_STREAM as Int32.
    #endif

    var results: UnsafeMutablePointer<addrinfo>?
    let status = getaddrinfo(host, nil, &hints, &results)
    defer {
      if let results {
        freeaddrinfo(results)
      }
    }
    guard status == 0, results != nil else {
      throw AddressResolutionError.unresolvable(host: host)
    }

    var addresses: [ResolvedAddress] = []
    var cursor = results

    while let info = cursor {
      if info.pointee.ai_family == AF_INET, let rawAddress = info.pointee.ai_addr {
        rawAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
          addresses.append(.ipv4(UInt32(bigEndian: pointer.pointee.sin_addr.s_addr)))
        }
      } else if info.pointee.ai_family == AF_INET6, let rawAddress = info.pointee.ai_addr {
        rawAddress.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { pointer in
          var v6Address = pointer.pointee.sin6_addr
          let bytes = withUnsafeBytes(of: &v6Address) { raw in Array(raw) }
          addresses.append(.ipv6(bytes))
        }
      }
      cursor = info.pointee.ai_next
    }

    guard addresses.isEmpty == false else {
      throw AddressResolutionError.unresolvable(host: host)
    }

    return addresses
  }
}
