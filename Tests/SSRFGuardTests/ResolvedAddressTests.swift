import Foundation
import SSRFGuard
import Testing

@Suite struct ResolvedAddressTests {
  @Test(arguments: ["198.18.0.84", "10.0.0.5", "169.254.169.254", "2001:db8::1", "::1", "fe80::1"])
  func rendersParsedLiteralBackToText(_ text: String) throws {
    // given
    let address = try #require(ResolvedAddress.parse(text), "unparseable fixture: \(text)")

    // when / then — the round-trip pins the inet_ntop plumbing for both families
    #expect("\(address)" == text)
  }

  @Test func parseRejectsGarbage() {
    // given / when / then
    #expect(ResolvedAddress.parse("not-an-ip") == nil)
    #expect(ResolvedAddress.parse("999.1.1.1") == nil)
    #expect(ResolvedAddress.parse("") == nil)
  }

  @Test(arguments: [
    // canonical literals
    "198.18.0.84", "10.0.0.5", "::1", "2001:db8::1",
    // legacy numeric IPv4 spellings getaddrinfo resolves without DNS
    "3323068500", "0xC6120054", "198.18", "0300.0030.0000.0124"
  ])
  func denotesIPLiteralAcceptsEveryNumericHostForm(_ host: String) {
    // given / when / then — the classifier must catch the forms strict inet_pton misses, so an
    // obfuscated literal cannot slip past a literal check by masquerading as a name
    #expect(ResolvedAddress.denotesIPLiteral(host: host), "\(host) must count as a literal")
  }

  @Test(arguments: ["example.com", "blog.jetbrains.com", "1password.com", "localhost", "a.b.c"])
  func denotesIPLiteralRejectsRealHostnames(_ host: String) {
    // given / when / then — DNS names (including digit-leading ones) are not literals
    #expect(ResolvedAddress.denotesIPLiteral(host: host) == false, "\(host) is not a literal")
  }
}
