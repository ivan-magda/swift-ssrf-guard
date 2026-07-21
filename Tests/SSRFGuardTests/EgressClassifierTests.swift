import Foundation
import SSRFGuard
import Testing

@Suite struct EgressClassifierTests {
  private static let classifier = EgressClassifier()

  // Every address here must be refused by the strict policy.
  private static let blockedAddresses: [String] = [
    // loopback
    "127.0.0.1", "127.8.8.8", "::1",
    // RFC 1918
    "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.1.1",
    // link-local (including the cloud metadata endpoint) and v6 link-local
    "169.254.0.1", "169.254.169.254", "fe80::1", "febf::1",
    // CGNAT
    "100.64.0.1", "100.127.255.254",
    // ULA
    "fc00::1", "fdff::1",
    // unspecified
    "0.0.0.0", "::",
    // multicast / broadcast
    "224.0.0.1", "239.255.255.255", "255.255.255.255", "ff02::1",
    // IETF protocol assignments (192.0.0.0/24)
    "192.0.0.1",
    // reserved / documentation
    "192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1", "240.0.0.1", "2001:db8::1",
    // IPv4-mapped IPv6 wrapping a private address (unwrapped and re-checked)
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:192.168.0.1", "::ffff:169.254.169.254",
    // NAT64 (64:ff9b::/96) wrapping loopback / the cloud-metadata endpoint
    "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
    // IPv4-compatible ::a.b.c.d (deprecated) wrapping loopback / a private address
    "::127.0.0.1", "::10.0.0.1"
  ]

  private static let publicAddresses: [String] = [
    "93.184.216.34",  // example.com
    "8.8.8.8",
    "1.1.1.1",
    "172.15.0.1",  // just below RFC 1918 172.16/12
    "172.32.0.1",  // just above it
    "100.63.255.255",  // just below CGNAT
    "100.128.0.0",  // just above it
    "9.255.255.255",  // just below 10/8
    "11.0.0.0",  // just above it
    "2606:2800:220:1:248:1893:25c8:1946",  // example.com v6
    "::ffff:8.8.8.8",  // mapped PUBLIC v4 is fine
    "64:ff9b::808:808",  // NAT64 wrapping a PUBLIC v4 (8.8.8.8) must still be allowed
    // IPv6 addresses just outside each blocked v6 prefix (boundary coverage)
    "2001::1",  // global unicast, not documentation 2001:db8::/32
    "2001:db7::1", "2001:db9::1",  // adjacent to 2001:db8::/32
    "fbff::1",  // just below ULA fc00::/7
    "fe00::1"  // just below link-local fe80::/10
  ]

  @Test(arguments: blockedAddresses)
  func refusesNonPublicAddress(_ text: String) throws {
    // given
    let address = try #require(ResolvedAddress.parse(text), "unparseable fixture: \(text)")

    // when / then
    #expect(Self.classifier.isAllowed(address) == false, "\(text) must be refused")
    #expect(Self.classifier.classify(address) != .allowed, "\(text) must not be allowed")
  }

  @Test(arguments: publicAddresses)
  func allowsPublicAddress(_ text: String) throws {
    // given
    let address = try #require(ResolvedAddress.parse(text), "unparseable fixture: \(text)")

    // when / then
    #expect(Self.classifier.isAllowed(address), "\(text) must be allowed")
    #expect(Self.classifier.classify(address) == .allowed, "\(text) must classify as allowed")
  }

  @Test func reportsTheMatchedRangeForABlockedAddress() throws {
    // given
    let address = try #require(ResolvedAddress.parse("10.0.0.1"))
    let expectedRange = try #require(CIDR.parse("10.0.0.0/8"))

    // when / then
    #expect(Self.classifier.classify(address) == .blocked(.matchedRange(expectedRange)))
  }

  @Test func unwrapsMappedIPv6ToTheEmbeddedV4RangeBeforeReporting() throws {
    // given — a private v4 wrapped in IPv4-mapped IPv6
    let address = try #require(ResolvedAddress.parse("::ffff:192.168.0.1"))
    let expectedRange = try #require(CIDR.parse("192.168.0.0/16"))

    // when / then — the reported range is the embedded v4 block, not a v6 block
    #expect(Self.classifier.classify(address) == .blocked(.matchedRange(expectedRange)))
  }

  @Test func failsClosedOnMalformedIPv6() {
    // given — an IPv6 value that is not the required sixteen bytes
    let malformed = ResolvedAddress.ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    // when / then
    #expect(Self.classifier.classify(malformed) == .blocked(.malformed))
    #expect(Self.classifier.isAllowed(malformed) == false)
  }

  @Test func honorsACustomPolicyByBlockingAnOtherwisePublicRange() throws {
    // given — a classifier that also refuses one public block
    let corporate = try #require(CIDR.parse("93.184.216.0/24"))
    let classifier = EgressClassifier(policy: .strict.adding([corporate]))
    let address = try #require(ResolvedAddress.parse("93.184.216.34"))

    // when / then — strict alone allows it; the added range refuses it
    #expect(EgressClassifier().isAllowed(address))
    #expect(classifier.classify(address) == .blocked(.matchedRange(corporate)))
  }
}
