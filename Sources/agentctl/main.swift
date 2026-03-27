import Foundation
import SSHAgentCore

@main
struct AgentCtl {
    static func main() {
        do {
            try run()
        } catch let error as SSHAgentCoreError {
            fputs("error: \(error.localizedDescription)\n", stderr)
            exit(1)
        } catch {
            fputs("error: \(error)\n", stderr)
            exit(1)
        }
    }

    private static func run() throws {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let command = args.first else {
            printUsage()
            return
        }
        guard command == "key" else {
            throw SSHAgentCoreError.unsupportedCommand(command)
        }

        let keyArgs = Array(args.dropFirst())
        guard let subcommand = keyArgs.first else {
            printKeyUsage()
            return
        }

        let store = SecureEnclaveKeyStore()
        switch subcommand {
        case "create":
            let options = try parseCreateOptions(Array(keyArgs.dropFirst()))
            let key = try store.createKey(name: options.name, comment: options.comment)
            print("created key:")
            print("  id: \(key.id)")
            print("  name: \(key.name)")
            print("  comment: \(key.comment)")
            print("  created: \(iso8601(key.createdAt))")
            print("  fingerprint: \(key.fingerprint)")
            print("  public-key: \(key.publicKey)")

        case "list":
            let showPublic = try parseListOptions(Array(keyArgs.dropFirst()))
            let keys = try store.listKeys()
            if keys.isEmpty {
                print("no managed keys found")
                return
            }

            for (index, key) in keys.enumerated() {
                print("\(index + 1). \(key.name)")
                print("   id: \(key.id)")
                print("   comment: \(key.comment)")
                print("   created: \(iso8601(key.createdAt))")
                print("   fingerprint: \(key.fingerprint)")
                if showPublic {
                    print("   public-key: \(key.publicKey)")
                }
            }

        default:
            throw SSHAgentCoreError.unsupportedCommand("key \(subcommand)")
        }
    }

    private static func parseCreateOptions(_ args: [String]) throws -> (name: String, comment: String) {
        var name = ""
        var comment = ""
        var index = 0

        while index < args.count {
            let token = args[index]
            switch token {
            case "--name":
                let nextIndex = index + 1
                guard nextIndex < args.count else {
                    throw SSHAgentCoreError.missingValue("--name")
                }
                name = args[nextIndex]
                index += 2
            case "--comment":
                let nextIndex = index + 1
                guard nextIndex < args.count else {
                    throw SSHAgentCoreError.missingValue("--comment")
                }
                comment = args[nextIndex]
                index += 2
            default:
                throw SSHAgentCoreError.invalidOption(token)
            }
        }

        return (name: name, comment: comment)
    }

    private static func parseListOptions(_ args: [String]) throws -> Bool {
        var showPublic = false
        for token in args {
            switch token {
            case "--public":
                showPublic = true
            default:
                throw SSHAgentCoreError.invalidOption(token)
            }
        }
        return showPublic
    }

    private static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    private static func printUsage() {
        print(
            """
            usage:
              agentctl key create [--name <name>] [--comment <comment>]
              agentctl key list [--public]
            """
        )
    }

    private static func printKeyUsage() {
        print(
            """
            usage:
              agentctl key create [--name <name>] [--comment <comment>]
              agentctl key list [--public]
            """
        )
    }
}
