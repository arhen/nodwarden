import AppKit
import Combine
import LocalAuthentication
import SwiftUI

enum Tools {
    static let searchPath: [String] = (ProcessInfo.processInfo.environment["NODWARDEN_PATH"] ?? [
        "\(NSHomeDirectory())/.n/bin", "\(NSHomeDirectory())/.volta/bin", "\(NSHomeDirectory())/.local/bin",
        "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
    ].joined(separator: ":")).split(separator: ":").map(String.init)

    /// Where the tool was found, and the real file behind every symlink
    /// (e.g. ~/.n/bin/bw -> ../lib/.../bw.js).
    struct Tool {
        let found: String
        let real: String
    }

    /// The core is the only resolver (#23): `aac-core --tools` walks every path with the trust
    /// check and prints the result. One implementation of security code, not two.
    static let report: [String: [String: String]] = {
        let core = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("aac-core").path ?? ""
        let p = Process()
        p.executableURL = URL(fileURLWithPath: core)
        p.arguments = ["--tools"]
        p.environment = ["PATH": searchPath.joined(separator: ":"), "HOME": NSHomeDirectory()]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return [:] }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: [String: String]] ?? [:]
    }()

    static func tool(_ name: String) -> Tool? {
        guard let e = report[name], let found = e["found"], let real = e["real"] else { return nil }
        return Tool(found: found, real: real)
    }

    /// Why a tool was refused or missing, for `--tools` and the status panel.
    static func problem(_ name: String) -> String? { report[name]?["error"] }

    static let nodeTool = tool("node")
    static let bwTool = tool("bw")
    static let node = nodeTool?.real
    static let bw = bwTool?.real
    static let bwbio = tool("bwbio")?.real

    /// PATH handed to child processes: only the directories the tools were found in.
    static var childPath: String {
        let dirs = [nodeTool, bwTool].compactMap { $0 }.flatMap { [$0.found, $0.real] }
            .map { URL(fileURLWithPath: $0).deletingLastPathComponent().path }
        var seen = Set<String>()
        return (dirs + ["/usr/bin", "/bin"]).filter { seen.insert($0).inserted }.joined(separator: ":")
    }

    /// Environment for aac-core. It takes `node` and `bw` by absolute path: the real `bw.js`
    /// is usually in a directory that has no file called `bw`, so PATH can't find it.
    static var coreEnvironment: [String: String] {
        var env = ["PATH": childPath, "HOME": NSHomeDirectory()]
        env["NODWARDEN_NODE"] = node
        env["NODWARDEN_BW"] = bw
        return env
    }
}
