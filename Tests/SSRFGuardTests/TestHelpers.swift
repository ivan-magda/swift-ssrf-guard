import SSRFGuard

/// Scripted resolver for tests: an IP literal parses directly (and never consults the table), a
/// named host resolves from the injected table, and an unknown host throws `.unresolvable`.
struct ScriptedResolver: AddressResolving {
  let table: [String: [ResolvedAddress]]

  func resolve(host: String) async throws -> [ResolvedAddress] {
    if let literal = ResolvedAddress.parse(host) {
      return [literal]
    }
    guard let addresses = table[host] else {
      throw AddressResolutionError.unresolvable(host: host)
    }
    return addresses
  }
}

/// Captures a thrown error of a given type. Swift 6.0's bundled swift-testing returns `Void` from
/// `#expect(throws:)`, so a test that inspects the thrown value captures it this way instead.
func captureError<E: Error>(
  _ type: E.Type,
  _ body: () async throws -> Void
) async -> E? {
  do {
    try await body()
    return nil
  } catch let error as E {
    return error
  } catch {
    return nil
  }
}
