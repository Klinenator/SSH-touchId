import Foundation
import XCTest
@testable import SSHAgentCore

final class OpenSSHPublicKeyEncoderTests: XCTestCase {
    func testEncodeFromX963BuildsExpectedOpenSSHPrefix() throws {
        let raw = mockX963PublicKey()
        let line = try OpenSSHPublicKeyEncoder.encodeFromX963(rawPublicKey: raw, comment: "demo-comment")

        let parts = line.split(separator: " ", maxSplits: 2).map(String.init)
        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(parts[0], "ecdsa-sha2-nistp256")
        XCTAssertEqual(parts[2], "demo-comment")
    }

    func testFingerprintFromX963UsesSHA256Format() throws {
        let raw = mockX963PublicKey()
        let fingerprint = try OpenSSHPublicKeyEncoder.fingerprintFromX963(rawPublicKey: raw)

        XCTAssertTrue(fingerprint.hasPrefix("SHA256:"))
        XCTAssertFalse(fingerprint.contains("="))
    }

    func testEncodeFromX963RejectsInvalidLength() {
        let raw = Data([0x04, 0x01, 0x02])

        XCTAssertThrowsError(try OpenSSHPublicKeyEncoder.encodeFromX963(rawPublicKey: raw, comment: "x")) { error in
            XCTAssertEqual(error as? SSHAgentCoreError, .invalidPublicKeyFormat)
        }
    }

    func testSignatureBlobFromRawECDSAHasExpectedAlgorithmPrefix() throws {
        let raw = Data((0..<64).map { UInt8(($0 + 1) & 0xFF) })
        let blob = try OpenSSHPublicKeyEncoder.signatureBlobFromRawECDSA(rawSignature: raw)

        let firstStringLength = UInt32(blob[0]) << 24 | UInt32(blob[1]) << 16 | UInt32(blob[2]) << 8 | UInt32(blob[3])
        let algorithm = String(data: blob[4..<(4 + Int(firstStringLength))], encoding: .utf8)
        XCTAssertEqual(algorithm, "ecdsa-sha2-nistp256")
    }
}

private func mockX963PublicKey() -> Data {
    var bytes = [UInt8](repeating: 0, count: 65)
    bytes[0] = 0x04
    for i in 1..<65 {
        bytes[i] = UInt8(i & 0xFF)
    }
    return Data(bytes)
}
