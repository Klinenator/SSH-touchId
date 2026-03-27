import Foundation

public enum SSHAgentMessageType: UInt8 {
    case failure = 5
    case success = 6
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
}

public struct SSHSignRequest: Equatable {
    public let keyBlob: Data
    public let dataToSign: Data
    public let flags: UInt32

    public init(keyBlob: Data, dataToSign: Data, flags: UInt32) {
        self.keyBlob = keyBlob
        self.dataToSign = dataToSign
        self.flags = flags
    }
}

public enum SSHAgentMessage: Equatable {
    case requestIdentities
    case signRequest(SSHSignRequest)
    case unknown(type: UInt8, payload: Data)
}

public enum SSHAgentProtocolError: Error, Equatable {
    case emptyFrame
    case frameTooLarge(length: UInt32, maxLength: UInt32)
    case malformedSignRequest
    case unexpectedPayload
}

public struct SSHAgentFrameDecoder {
    private(set) var buffer = Data()
    public let maxFrameLength: UInt32

    public init(maxFrameLength: UInt32 = 1_048_576) {
        self.maxFrameLength = maxFrameLength
    }

    public mutating func append(_ bytes: Data) throws -> [Data] {
        buffer.append(bytes)
        var frames: [Data] = []

        while buffer.count >= 4 {
            let length = decodeUInt32(buffer[0...3])
            if length > maxFrameLength {
                throw SSHAgentProtocolError.frameTooLarge(length: length, maxLength: maxFrameLength)
            }

            let totalBytes = Int(length) + 4
            if buffer.count < totalBytes {
                break
            }

            let frame = buffer.subdata(in: 4..<totalBytes)
            frames.append(frame)
            buffer.removeSubrange(0..<totalBytes)
        }

        return frames
    }

    public mutating func reset() {
        buffer.removeAll(keepingCapacity: true)
    }
}

public struct SSHAgentMessageParser {
    public init() {}

    public func parse(frame: Data) throws -> SSHAgentMessage {
        guard let type = frame.first else {
            throw SSHAgentProtocolError.emptyFrame
        }

        let payload = Data(frame.dropFirst())

        switch type {
        case SSHAgentMessageType.requestIdentities.rawValue:
            guard payload.isEmpty else {
                throw SSHAgentProtocolError.unexpectedPayload
            }
            return .requestIdentities

        case SSHAgentMessageType.signRequest.rawValue:
            var cursor = SSHByteCursor(data: payload)
            guard
                let keyBlob = cursor.readSSHString(),
                let dataToSign = cursor.readSSHString(),
                let flags = cursor.readUInt32(),
                cursor.isAtEnd
            else {
                throw SSHAgentProtocolError.malformedSignRequest
            }
            return .signRequest(SSHSignRequest(keyBlob: keyBlob, dataToSign: dataToSign, flags: flags))

        default:
            return .unknown(type: type, payload: payload)
        }
    }
}

public struct SSHAgentIdentity: Equatable {
    public let keyBlob: Data
    public let comment: String

    public init(keyBlob: Data, comment: String) {
        self.keyBlob = keyBlob
        self.comment = comment
    }
}

public enum SSHAgentResponseEncoder {
    public static func failureFrame() -> Data {
        frame(payload: Data([SSHAgentMessageType.failure.rawValue]))
    }

    public static func successFrame() -> Data {
        frame(payload: Data([SSHAgentMessageType.success.rawValue]))
    }

    public static func identitiesAnswerFrame(_ identities: [SSHAgentIdentity]) -> Data {
        var payload = Data([SSHAgentMessageType.identitiesAnswer.rawValue])
        payload.append(encodeUInt32(UInt32(identities.count)))
        for identity in identities {
            payload.append(encodeSSHString(identity.keyBlob))
            payload.append(encodeSSHString(Data(identity.comment.utf8)))
        }
        return frame(payload: payload)
    }

    public static func signResponseFrame(signatureBlob: Data) -> Data {
        var payload = Data([SSHAgentMessageType.signResponse.rawValue])
        payload.append(encodeSSHString(signatureBlob))
        return frame(payload: payload)
    }

    private static func frame(payload: Data) -> Data {
        var data = Data()
        data.append(encodeUInt32(UInt32(payload.count)))
        data.append(payload)
        return data
    }

    private static func encodeSSHString(_ value: Data) -> Data {
        var data = Data()
        data.append(encodeUInt32(UInt32(value.count)))
        data.append(value)
        return data
    }
}

private struct SSHByteCursor {
    let data: Data
    var offset: Int = 0

    var isAtEnd: Bool {
        offset == data.count
    }

    mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= data.count else {
            return nil
        }
        let value = decodeUInt32(data[offset..<(offset + 4)])
        offset += 4
        return value
    }

    mutating func readSSHString() -> Data? {
        guard let stringLength = readUInt32() else {
            return nil
        }
        let count = Int(stringLength)
        guard offset + count <= data.count else {
            return nil
        }
        let value = data.subdata(in: offset..<(offset + count))
        offset += count
        return value
    }
}

private func decodeUInt32<T: Collection>(_ bytes: T) -> UInt32 where T.Element == UInt8 {
    var result: UInt32 = 0
    for byte in bytes {
        result = (result << 8) | UInt32(byte)
    }
    return result
}

private func encodeUInt32(_ value: UInt32) -> Data {
    Data([
        UInt8((value >> 24) & 0xFF),
        UInt8((value >> 16) & 0xFF),
        UInt8((value >> 8) & 0xFF),
        UInt8(value & 0xFF),
    ])
}
