// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AuthService",
    platforms: [
        .iOS(.v14),
        .macOS(.v12)
    ],
    products: [
        .library(name: "AuthService", targets: ["AuthService"])
    ],
    targets: [
        .target(
            name: "AuthService",
            path: ".",
            exclude: [
                "README.md",
                "Tests"
            ],
            sources: [
                "AuthServiceClient.swift",
                "AuthServiceKeychainTokenStore.swift"
            ]
        ),
        .testTarget(
            name: "AuthServiceTests",
            dependencies: ["AuthService"],
            path: "Tests/AuthServiceTests"
        )
    ]
)
