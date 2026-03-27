// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "touchid-ssh-agent",
    platforms: [
        .macOS(.v13),
    ],
    targets: [
        .target(
            name: "SSHAgentCore"
        ),
        .target(
            name: "SSHAgentProtocol"
        ),
        .executableTarget(
            name: "touchid-ssh-agent",
            dependencies: ["SSHAgentProtocol", "SSHAgentCore"]
        ),
        .executableTarget(
            name: "agentctl",
            dependencies: ["SSHAgentCore"]
        ),
        .executableTarget(
            name: "ssh-agent-protocol-selftest",
            dependencies: ["SSHAgentProtocol"]
        ),
        .testTarget(
            name: "SSHAgentCoreTests",
            dependencies: ["SSHAgentCore"]
        ),
        .testTarget(
            name: "SSHAgentProtocolTests",
            dependencies: ["SSHAgentProtocol"]
        ),
    ]
)
