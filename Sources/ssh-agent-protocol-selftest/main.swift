import Foundation
import SSHAgentProtocol

@main
struct SSHAgentProtocolSelfTest {
    static func main() throws {
        try testFrameDecoderWaitsForCompleteHeaderAndPayload()
        try testFrameDecoderParsesMultipleFramesFromSingleChunk()
        try testParserDecodesRequestIdentities()
        try testParserDecodesSignRequest()
        try testParserRejectsMalformedSignRequest()
        print("all phase0 protocol checks passed")
    }

    private static func testFrameDecoderWaitsForCompleteHeaderAndPayload() throws {
        var decoder = SSHAgentFrameDecoder()
        let payload = Data([SSHAgentMessageType.requestIdentities.rawValue])
        let framed = makeFrame(payload)

        try assertOrThrow(try decoder.append(Data(framed.prefix(3))).count == 0, "expected no frame after partial header")
        try assertOrThrow(try decoder.append(Data(framed.dropFirst(3).prefix(1))).count == 0, "expected no frame after header only")

        let frames = try decoder.append(Data(framed.dropFirst(4)))
        try assertOrThrow(frames == [payload], "expected one completed payload frame")
    }

    private static func testFrameDecoderParsesMultipleFramesFromSingleChunk() throws {
        var decoder = SSHAgentFrameDecoder()
        let first = Data([SSHAgentMessageType.requestIdentities.rawValue])
        let second = Data([0xFF, 0x01, 0x02])
        let stream = makeFrame(first) + makeFrame(second)

        let frames = try decoder.append(stream)
        try assertOrThrow(frames == [first, second], "expected two frames from single stream chunk")
    }

    private static func testParserDecodesRequestIdentities() throws {
        let parser = SSHAgentMessageParser()
        let message = try parser.parse(frame: Data([SSHAgentMessageType.requestIdentities.rawValue]))
        try assertOrThrow(message == .requestIdentities, "expected request-identities message")
    }

    private static func testParserDecodesSignRequest() throws {
        let parser = SSHAgentMessageParser()

        let keyBlob = Data([0xAA, 0xBB, 0xCC])
        let dataToSign = Data("hello".utf8)
        let flags: UInt32 = 2

        var frame = Data([SSHAgentMessageType.signRequest.rawValue])
        frame.append(makeSSHString(keyBlob))
        frame.append(makeSSHString(dataToSign))
        frame.append(encodeUInt32(flags))

        let message = try parser.parse(frame: frame)
        let expected = SSHAgentMessage.signRequest(SSHSignRequest(keyBlob: keyBlob, dataToSign: dataToSign, flags: flags))
        try assertOrThrow(message == expected, "expected parsed sign-request payload")
    }

    private static func testParserRejectsMalformedSignRequest() throws {
        let parser = SSHAgentMessageParser()
        var frame = Data([SSHAgentMessageType.signRequest.rawValue])
        frame.append(makeSSHString(Data([0x00, 0x01])))

        do {
            _ = try parser.parse(frame: frame)
            throw SelfTestError.failed("expected malformed sign-request error")
        } catch let error as SSHAgentProtocolError {
            try assertOrThrow(error == .malformedSignRequest, "expected malformed-sign-request error type")
        }
    }
}

private enum SelfTestError: Error {
    case failed(String)
}

private func assertOrThrow(_ condition: Bool, _ message: String) throws {
    guard condition else {
        throw SelfTestError.failed(message)
    }
}

private func makeFrame(_ payload: Data) -> Data {
    encodeUInt32(UInt32(payload.count)) + payload
}

private func makeSSHString(_ value: Data) -> Data {
    encodeUInt32(UInt32(value.count)) + value
}

private func encodeUInt32(_ value: UInt32) -> Data {
    Data([
        UInt8((value >> 24) & 0xFF),
        UInt8((value >> 16) & 0xFF),
        UInt8((value >> 8) & 0xFF),
        UInt8(value & 0xFF),
    ])
}
