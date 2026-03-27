import Foundation
import XCTest
@testable import SSHAgentProtocol

final class SSHAgentResponseEncoderTests: XCTestCase {
    func testFailureFrameEncodesFailureType() {
        let frame = SSHAgentResponseEncoder.failureFrame()
        XCTAssertEqual(frame.count, 5)
        XCTAssertEqual(frame[4], SSHAgentMessageType.failure.rawValue)
    }

    func testIdentitiesAnswerIncludesIdentityCount() {
        let identity = SSHAgentIdentity(keyBlob: Data([0x01, 0x02]), comment: "demo")
        let frame = SSHAgentResponseEncoder.identitiesAnswerFrame([identity])

        XCTAssertEqual(frame[4], SSHAgentMessageType.identitiesAnswer.rawValue)

        let countOffset = 5
        let count = UInt32(frame[countOffset]) << 24 |
            UInt32(frame[countOffset + 1]) << 16 |
            UInt32(frame[countOffset + 2]) << 8 |
            UInt32(frame[countOffset + 3])
        XCTAssertEqual(count, 1)
    }
}
