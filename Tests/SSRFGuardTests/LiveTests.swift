import Foundation
import SSRFGuard
import Testing

/// Opt-in live check: resolves a real public hostname over the network and asserts it classifies
/// as allowed. Enable with `SSRFGUARD_LIVE_TESTS=1`; skipped by default so the suite stays
/// deterministic and offline.
@Suite(.enabled(if: ProcessInfo.processInfo.environment["SSRFGUARD_LIVE_TESTS"] == "1"))
struct LiveTests {
  @Test func resolvesAndAllowsAPublicHost() async throws {
    // given
    let resolver = SystemAddressResolver()
    let classifier = EgressClassifier()

    // when
    let addresses = try await resolver.resolve(host: "example.com")

    // then
    #expect(addresses.isEmpty == false)
    #expect(addresses.allSatisfy { address in classifier.isAllowed(address) })
  }
}
