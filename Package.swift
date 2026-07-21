// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "swift-ssrf-guard",
  platforms: [
    .iOS(.v16),
    .macOS(.v13),
    .tvOS(.v16),
    .watchOS(.v9),
    .visionOS(.v1),
  ],
  products: [
    .library(
      name: "SSRFGuard",
      targets: ["SSRFGuard"]
    )
  ],
  dependencies: [
    .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0")
  ],
  targets: [
    .target(
      name: "SSRFGuard"
    ),
    .testTarget(
      name: "SSRFGuardTests",
      dependencies: ["SSRFGuard"]
    ),
  ]
)
