// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "tauri-plugin-gaugedesk-device-identity",
    platforms: [
        .iOS(.v14),
    ],
    products: [
        .library(
            name: "tauri-plugin-gaugedesk-device-identity",
            type: .static,
            targets: ["GaugeDeskDeviceIdentityPlugin"]
        ),
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api"),
    ],
    targets: [
        .target(
            name: "GaugeDeskDeviceIdentityPlugin",
            dependencies: [
                .byName(name: "Tauri"),
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "GaugeDeskDeviceIdentityPluginTests",
            dependencies: ["GaugeDeskDeviceIdentityPlugin"],
            path: "Tests",
            exclude: ["RegistryParityMain.swift"]
        ),
    ]
)
