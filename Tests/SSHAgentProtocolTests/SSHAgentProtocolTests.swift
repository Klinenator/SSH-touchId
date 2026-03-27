import XCTest
@testable import SSHAgentProtocol

final class SSHAgentProtocolTests: XCTestCase {
    func testFrameDecoderWaitsForCompleteHeaderAndPayload() throws {
        var decoder = SSHAgentFrameDecoder()
        let payload = Data([SSHAgentMessageType.requestIdentities.rawValue])
        let framed = makeFrame(payload)

        XCTAssertEqual(try decoder.append(framed.prefix(3).asData()).count, 0)
        XCTAssertEqual(try decoder.append(framed.dropFirst(3).prefix(1).asData()).count, 0)

        let frames = try decoder.append(framed.dropFirst(4).asData())
        XCTAssertEqual(frames, [payload])
    }

    func testFrameDecoderParsesMultipleFramesFromSingleChunk() throws {
        var decoder = SSHAgentFrameDecoder()
        let first = Data([SSHAgentMessageType.requestIdentities.rawValue])
        let second = Data([0xFF, 0x01, 0x02])
        let stream = makeFrame(first) + makeFrame(second)

        let frames = try decoder.append(stream)
        XCTAssertEqual(frames, [first, second])
    }

    func testParserDecodesRequestIdentities() throws {
        let parser = SSHAgentMessageParser()
        let message = try parser.parse(frame: Data([SSHAgentMessageType.requestIdentities.rawValue]))
        XCTAssertEqual(message, .requestIdentities)
    }

    func testParserDecodesSignRequest() throws {
        let parser = SSHAgentMessageParser()

        let keyBlob = Data([0xAA, 0xBB, 0xCC])
        let dataToSign = Data("hello".utf8)
        let flags: UInt32 = 2

        var frame = Data([SSHAgentMessageType.signRequest.rawValue])
        frame.append(makeSSHString(keyBlob))
        frame.append(makeSSHString(dataToSign))
        frame.append(encodeUInt32(flags))

        let message = try parser.parse(frame: frame)
        XCTAssertEqual(
            message,
            .signRequest(SSHSignRequest(keyBlob: keyBlob, dataToSign: dataToSign, flags: flags))
        )
    }

    func testParserRejectsMalformedSignRequest() {
        let parser = SSHAgentMessageParser()
        var frame = Data([SSHAgentMessageType.signRequest.rawValue])
        frame.append(makeSSHString(Data([0x00, 0x01])))

        XCTAssertThrowsError(try parser.parse(frame: frame)) { error in
            XCTAssertEqual(error as? SSHAgentProtocolError, .malformedSignRequest)
        }
    }
}

private extension Collection where Element == UInt8 {
    func asData() -> Data {
        Data(self)
    }
}

private func makeFrame(_ payload: Data) -> Data {
    encodeUInt32(UInt32(payload.count)) + payload
}

private func makeSSHString(_ value: Data) -> Data {
    encodeUInt32(UInt32(value.count)) + value
}

private func encodeUInt32(_ value: UInt32) -> Data {
    let bytes: [UInt8] = [
        UInt8((value >> 24) & 0xFF),
        UInt8((value >> 16) & 0xFF),
        UInt8((value >> 8) & 0xFF),
        UInt8(value & 0xFF),
    ]
    return Data(bytes)
}
