import Foundation
import SSRFGuard
import Testing

@Suite struct SystemAddressResolverTests {
  @Test func resolvesTheLoopbackNameWithoutTheNetwork() async throws {
    // given — "localhost" resolves locally; this pins the getaddrinfo plumbing
    let resolver = SystemAddressResolver()
    let classifier = EgressClassifier()

    // when
    let addresses = try await resolver.resolve(host: "localhost")

    // then
    #expect(addresses.isEmpty == false)
    #expect(addresses.allSatisfy { address in classifier.isAllowed(address) == false })
  }

  @Test func shortCircuitsALiteralWithoutHittingDNS() async throws {
    // given
    let resolver = SystemAddressResolver()
    let expected = try #require(ResolvedAddress.parse("127.0.0.1"))

    // when
    let addresses = try await resolver.resolve(host: "127.0.0.1")

    // then — a literal parses locally; it must never reach a lookup
    #expect(addresses == [expected])
  }

  @Test func scriptedResolverReturnsTheTableEntryForANamedHost() async throws {
    // given
    let mapped = try #require(ResolvedAddress.parse("93.184.216.34"))
    let resolver = ScriptedResolver(table: ["example.test": [mapped]])

    // when
    let addresses = try await resolver.resolve(host: "example.test")

    // then
    #expect(addresses == [mapped])
  }

  @Test func scriptedResolverThrowsForAnUnknownHost() async {
    // given
    let resolver = ScriptedResolver(table: [:])

    // when
    let error = await captureError(AddressResolutionError.self) {
      _ = try await resolver.resolve(host: "unknown.test")
    }

    // then
    #expect(error == .unresolvable(host: "unknown.test"))
  }
}
