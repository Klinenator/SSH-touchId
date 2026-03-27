import Darwin
import Dispatch
import Foundation
import LocalAuthentication
import SSHAgentCore
import SSHAgentProtocol

@main
struct touchid_ssh_agent {
    static func main() {
        do {
            let config = try AgentConfig.parse(arguments: Array(CommandLine.arguments.dropFirst()))
            let server = SSHAgentServer(config: config)
            try server.run()
        } catch {
            fputs("error: \(error)\n", stderr)
            exit(1)
        }
    }
}

private struct AgentConfig {
    let socketPath: String
    let authReason: String
    let keyID: String?

    static func parse(arguments: [String]) throws -> AgentConfig {
        var socketPath = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] ?? defaultSocketPath()
        var authReason = "Authorize SSH signature"
        var keyID = ProcessInfo.processInfo.environment["TOUCHID_AGENT_KEY_ID"]
        var index = 0

        while index < arguments.count {
            let token = arguments[index]
            switch token {
            case "--socket":
                let valueIndex = index + 1
                guard valueIndex < arguments.count else {
                    throw SSHAgentCoreError.missingValue("--socket")
                }
                socketPath = arguments[valueIndex]
                index += 2
            case "--reason":
                let valueIndex = index + 1
                guard valueIndex < arguments.count else {
                    throw SSHAgentCoreError.missingValue("--reason")
                }
                authReason = arguments[valueIndex]
                index += 2
            case "--key-id":
                let valueIndex = index + 1
                guard valueIndex < arguments.count else {
                    throw SSHAgentCoreError.missingValue("--key-id")
                }
                keyID = arguments[valueIndex]
                index += 2
            case "--help", "-h":
                printUsageAndExit()
            default:
                throw SSHAgentCoreError.invalidOption(token)
            }
        }

        return AgentConfig(socketPath: socketPath, authReason: authReason, keyID: keyID)
    }

    private static func defaultSocketPath() -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.ssh/touchid-agent.sock"
    }

    private static func printUsageAndExit() -> Never {
        print(
            """
            usage:
              touchid-ssh-agent [--socket <path>] [--reason <text>] [--key-id <uuid>]
            """
        )
        exit(0)
    }
}

private final class SSHAgentServer {
    private let config: AgentConfig
    private let keyStore = SecureEnclaveKeyStore()
    private let parser = SSHAgentMessageParser()
    private var serverFD: Int32 = -1
    private var shouldStop = false
    private var signalSources: [DispatchSourceSignal] = []

    init(config: AgentConfig) {
        self.config = config
    }

    func run() throws {
        try prepareSocketDirectory()
        try prepareSocketFile()
        try installSignalHandlers()

        serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFD >= 0 else {
            throw AgentRuntimeError.posix(errno)
        }

        do {
            try bindAndListen(serverFD)
            print("touchid-ssh-agent listening on \(config.socketPath)")
            while !shouldStop {
                let clientFD = accept(serverFD, nil, nil)
                if clientFD < 0 {
                    if shouldStop {
                        break
                    }
                    if errno == EINTR {
                        continue
                    }
                    throw AgentRuntimeError.posix(errno)
                }
                do {
                    try handleClient(fd: clientFD)
                } catch {
                    fputs("client error: \(error)\n", stderr)
                }
                _ = close(clientFD)
            }
            cleanupSocket()
        } catch {
            cleanupSocket()
            throw error
        }
    }

    private func handleClient(fd: Int32) throws {
        var decoder = SSHAgentFrameDecoder()
        var buffer = [UInt8](repeating: 0, count: 8192)

        while true {
            let count = read(fd, &buffer, buffer.count)
            if count == 0 {
                return
            }
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                throw AgentRuntimeError.posix(errno)
            }

            let frames = try decoder.append(Data(buffer[0..<count]))
            for frame in frames {
                let response = try handleFrame(frame)
                try writeAll(fd: fd, data: response)
            }
        }
    }

    private func handleFrame(_ frame: Data) throws -> Data {
        let message = try parser.parse(frame: frame)
        switch message {
        case .requestIdentities:
            do {
                let identities = try resolvedManagedKeys().map { managed in
                    SSHAgentIdentity(keyBlob: managed.keyBlob, comment: managed.comment)
                }
                return SSHAgentResponseEncoder.identitiesAnswerFrame(identities)
            } catch {
                fputs("identity listing failed: \(error)\n", stderr)
                return SSHAgentResponseEncoder.failureFrame()
            }

        case .signRequest(let signRequest):
            let keys: [ManagedKey]
            do {
                keys = try resolvedManagedKeys()
            } catch {
                fputs("sign key lookup failed: \(error)\n", stderr)
                return SSHAgentResponseEncoder.failureFrame()
            }

            guard let managed = keys.first(where: { $0.keyBlob == signRequest.keyBlob }) else {
                return SSHAgentResponseEncoder.failureFrame()
            }

            do {
                try authorizeWithTouchID(reason: "\(config.authReason): \(managed.name)")
                let rawSignature = try keyStore.sign(id: managed.id, data: signRequest.dataToSign)
                let signatureBlob = try OpenSSHPublicKeyEncoder.signatureBlobFromRawECDSA(rawSignature: rawSignature)
                return SSHAgentResponseEncoder.signResponseFrame(signatureBlob: signatureBlob)
            } catch {
                fputs("signing denied/failed: \(error)\n", stderr)
                return SSHAgentResponseEncoder.failureFrame()
            }

        case .unknown:
            return SSHAgentResponseEncoder.failureFrame()
        }
    }

    private func resolvedManagedKeys() throws -> [ManagedKey] {
        if let keyID = config.keyID, !keyID.isEmpty {
            return [try keyStore.loadManagedKey(id: keyID)]
        }
        return try keyStore.listKeys()
    }

    private func authorizeWithTouchID(reason: String) throws {
        let biometricsContext = LAContext()
        biometricsContext.localizedCancelTitle = "Deny"
        biometricsContext.localizedFallbackTitle = ""

        do {
            try evaluatePolicy(
                context: biometricsContext,
                policy: .deviceOwnerAuthenticationWithBiometrics,
                reason: reason
            )
            return
        } catch let laError as LAError where laError.code == .userFallback {
            // Some environments choose fallback auth; allow device-owner auth as a recovery path.
            let fallbackContext = LAContext()
            fallbackContext.localizedCancelTitle = "Deny"
            try evaluatePolicy(
                context: fallbackContext,
                policy: .deviceOwnerAuthentication,
                reason: reason
            )
        }
    }

    private func evaluatePolicy(context: LAContext, policy: LAPolicy, reason: String) throws {
        var evaluateError: NSError?
        guard context.canEvaluatePolicy(policy, error: &evaluateError) else {
            throw evaluateError ?? SSHAgentCoreError.secureEnclaveKeyUnavailable
        }

        let semaphore = DispatchSemaphore(value: 0)
        let authResult = AuthResultBox()

        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            authResult.set(success: success, error: error)
            semaphore.signal()
        }

        semaphore.wait()
        let result = authResult.read()
        if !result.success {
            throw result.error ?? SSHAgentCoreError.secureEnclaveKeyUnavailable
        }
    }

    private func prepareSocketDirectory() throws {
        let url = URL(fileURLWithPath: config.socketPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    private func prepareSocketFile() throws {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: config.socketPath) else {
            return
        }

        guard isUnixSocket(path: config.socketPath) else {
            throw SSHAgentCoreError.invalidOption("socket path exists and is not a unix socket: \(config.socketPath)")
        }

        if isSocketActive(path: config.socketPath) {
            throw SSHAgentCoreError.invalidOption("socket already in use: \(config.socketPath)")
        }

        _ = unlink(config.socketPath)
    }

    private func bindAndListen(_ fd: Int32) throws {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = Array(config.socketPath.utf8CString)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count <= maxLen else {
            throw SSHAgentCoreError.invalidOption("socket path too long")
        }

        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: maxLen) { sunPathPtr in
                sunPathPtr.initialize(repeating: 0, count: maxLen)
                for (index, byte) in pathBytes.enumerated() {
                    sunPathPtr[index] = byte
                }
            }
        }

        let bindResult: Int32 = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            throw AgentRuntimeError.posix(errno)
        }

        config.socketPath.withCString { cPath in
            _ = chmod(cPath, S_IRUSR | S_IWUSR)
        }

        guard listen(fd, 16) == 0 else {
            throw AgentRuntimeError.posix(errno)
        }
    }

    private func cleanupSocket() {
        shouldStop = true
        if serverFD >= 0 {
            _ = close(serverFD)
            serverFD = -1
        }
        _ = unlink(config.socketPath)
    }

    private func installSignalHandlers() throws {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let queue = DispatchQueue(label: "com.touchidsshagent.signals")
        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
        intSource.setEventHandler { [weak self] in
            self?.cleanupSocket()
        }
        intSource.resume()

        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        termSource.setEventHandler { [weak self] in
            self?.cleanupSocket()
        }
        termSource.resume()

        signalSources = [intSource, termSource]
    }

    private func isUnixSocket(path: String) -> Bool {
        var statBuffer = stat()
        let result = path.withCString { cPath in
            lstat(cPath, &statBuffer)
        }
        guard result == 0 else {
            return false
        }
        return (statBuffer.st_mode & S_IFMT) == S_IFSOCK
    }

    private func isSocketActive(path: String) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            return false
        }
        defer { _ = close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8CString)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count <= maxLen else {
            return false
        }

        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: maxLen) { sunPathPtr in
                sunPathPtr.initialize(repeating: 0, count: maxLen)
                for (index, byte) in pathBytes.enumerated() {
                    sunPathPtr[index] = byte
                }
            }
        }

        let rc: Int32 = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        return rc == 0
    }

    private func writeAll(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard var base = rawBuffer.baseAddress else {
                return
            }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = write(fd, base, remaining)
                if written < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw AgentRuntimeError.posix(errno)
                }
                remaining -= written
                base = base.advanced(by: written)
            }
        }
    }
}

private final class AuthResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var success = false
    private var error: Error?

    func set(success: Bool, error: Error?) {
        lock.lock()
        self.success = success
        self.error = error
        lock.unlock()
    }

    func read() -> (success: Bool, error: Error?) {
        lock.lock()
        let result = (success: self.success, error: self.error)
        lock.unlock()
        return result
    }
}

private enum AgentRuntimeError: Error, LocalizedError {
    case posix(Int32)

    var errorDescription: String? {
        switch self {
        case .posix(let code):
            return String(cString: strerror(code))
        }
    }
}
