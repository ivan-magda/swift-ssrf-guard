import Foundation
import SSRFGuard
import Testing

@Suite struct EgressPolicyTests {
  @Test func addingAppendsTheGivenRanges() throws {
    // given
    let base = EgressPolicy(blockedRanges: [])
    let range = try #require(CIDR.parse("192.0.2.0/24"))

    // when
    let extended = base.adding([range])

    // then
    #expect(base.blockedRanges.isEmpty)
    #expect(extended.blockedRanges == [range])
  }

  @Test func strictCoversBothAddressFamilies() throws {
    // given
    let ranges = EgressPolicy.strict.blockedRanges
    let loopbackV4 = try #require(CIDR.parse("127.0.0.0/8"))
    let linkLocalV6 = try #require(CIDR.parse("fe80::/10"))

    // when / then
    #expect(ranges.contains(loopbackV4))
    #expect(ranges.contains(linkLocalV6))
  }

  @Test func strictPinsTheExactExpectedRangeSet() throws {
    // given — the full strict deny-list, pinned so a dropped, added, or shifted range fails here
    let expected = [
      "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
      "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
      "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
      "fe80::/10", "fc00::/7", "ff00::/8", "2001:db8::/32"
    ].compactMap(CIDR.parse)

    // when / then
    #expect(expected.count == 18)
    #expect(EgressPolicy.strict.blockedRanges == expected)
  }

  @Test func anEmptyPolicyAllowsEveryWellFormedAddress() throws {
    // given — a policy with no blocked ranges is the only gate
    let classifier = EgressClassifier(policy: EgressPolicy(blockedRanges: []))
    let privateAddress = try #require(ResolvedAddress.parse("10.0.0.1"))

    // when / then — nothing is blocked, so even a private address is allowed
    #expect(classifier.isAllowed(privateAddress))
  }

  @Test func anEmptyPolicyStillFailsClosedOnMalformedInput() {
    // given — fail-closed on malformed input lives in the classifier, not the policy
    let classifier = EgressClassifier(policy: EgressPolicy(blockedRanges: []))

    // when / then
    #expect(classifier.classify(.ipv6([0])) == .blocked(.malformed))
  }
}
