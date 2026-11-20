import AppKit
import Combine
import LocalAuthentication
import Network
import SwiftUI

final class Core: ObservableObject {
    @Published var state: VaultState = .starting
    @Published var queue: [CredRequest] = []
    @Published var outcome: Outcome?
    @Published var unlocking = false
    /// The latest thing to tell you, shown as a card until it's resolved or replaced (#14).
    @Published var notice: Notice?
    /// The vault couldn't be synced: the keys come from the copy on this Mac. Shown as a quiet
    /// line, and a dot on the island, until a sync works.
    @Published var stale = false
    /// A sync is running (Retry, the automatic retry, or the network coming back).
    @Published var syncing = false
    /// Syncs as soon as the network comes back while on the offline copy, instead of waiting
    /// for the next automatic retry.
    private let network = NWPathMonitor()
    /// Open Allow windows, as the core reports them (#5): what each covers and when it ends.
    @Published var windows: [AllowWindow] = []
    /// Paired devices and unused tokens (#3), refreshed when the Agents view opens.
    @Published var paired: [Agent] = []
    @Published var tokens: [Agent] = []
    /// SSH keys loaded, for the header.
    @Published var keyCount = 0
    /// The reusable PSK token, when aac-core mints a new one (#19).
    @Published var token: String?
    /// Why the relay is not connected, while it isn't. Separate from the vault state: with
    /// the relay down the keys are still loaded and the SSH agent still signs, so the lock
    /// state and the Lock button must stay.
    @Published var relayNote: String?

    private var proc: Process?
    private var stdin: FileHandle?
    private var buffer = Data()
    private var outcomeWork: DispatchWorkItem?
    private var restartDelay: TimeInterval = 1

    var corePath: String {
        Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("aac-core").path
    }

    /// stderr of aac-core: ~/Library/Logs/NodWarden/aac-core.log, 0600, never a symlink (#16).
    /// Appended to, not truncated: the core is restarted a second after it dies, and its last
    /// words (a panic) are the reason to read this file. Started over once it passes 1 MB.
    static func openLog() -> FileHandle {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/NodWarden")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = dir.appendingPathComponent("aac-core.log").path
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return FileHandle.nullDevice }
        fchmod(fd, 0o600)
        var st = stat()
        if fstat(fd, &st) == 0, st.st_size > 1 << 20 { ftruncate(fd, 0) }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    func watchNetwork() {
        network.pathUpdateHandler = { [weak self] path in
            guard path.status == .satisfied else { return }
            DispatchQueue.main.async {
                guard let self, self.state == .unlocked, self.stale else { return }
                self.refresh()
            }
        }
        network.start(queue: DispatchQueue(label: "nodwarden.network"))
    }

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: corePath)
        p.environment = Tools.coreEnvironment
        let inPipe = Pipe(), outPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = outPipe
        p.standardError = Core.openLog()
        buffer.removeAll()
        outPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            if d.isEmpty {
                h.readabilityHandler = nil // EOF: stop the handler spinning (#8).
                return
            }
            DispatchQueue.main.async { self?.ingest(d) }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                guard let self else { return }
                self.stdin = nil
                self.proc = nil
                self.relayNote = nil
                for r in self.queue { self.flash(.cancelled(r.title)) }
                self.queue.removeAll()
                if case .offline = self.state {} else {
                    self.state = .offline(proc.terminationStatus == 0 ? "listener stopped" : "listener exited (\(proc.terminationStatus))")
                }
                // Back off up to a minute while offline (#8).
                let delay = self.restartDelay
                self.restartDelay = min(self.restartDelay * 2, 60)
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { self.start() }
            }
        }
        do { try p.run() } catch { state = .offline("cannot start aac-core"); return }
        proc = p
        stdin = inPipe.fileHandleForWriting
    }

    func stop() {
        send(["op": "lock"])
        proc?.terminationHandler = nil
        proc?.terminate()
        Core.bwLock()
    }

    /// Locks bw so a session copied from anywhere stops working. At most 5 s.
    static func bwLock() {
        guard let node = Tools.node, let bw = Tools.bw else { return }
        let lock = Process()
        lock.executableURL = URL(fileURLWithPath: node)
        lock.arguments = [bw, "lock"]
        lock.environment = ["HOME": NSHomeDirectory()]
        guard (try? lock.run()) != nil else { return }
        // Quitting must not hang on a bw that does.
        let killer = DispatchWorkItem { if lock.isRunning { lock.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: killer)
        lock.waitUntilExit()
        killer.cancel()
    }

    /// Writes go through one serial queue, so a core that stops reading can't hang the UI (#18),
    /// and lines never interleave.
    private let writer = DispatchQueue(label: "nodwarden.core-stdin")

    private func send(_ obj: [String: Any]) {
        guard let stdin, var d = try? JSONSerialization.data(withJSONObject: obj) else { return }
        d.append(0x0A)
        writer.async {
            // Throws instead of raising SIGPIPE on a dead pipe (#8).
            try? stdin.write(contentsOf: d)
            // The line may carry the vault session: wipe this copy once it's written (#11).
            d.resetBytes(in: 0..<d.count)
        }
    }

    private func ingest(_ d: Data) {
        buffer.append(d)
        while let nl = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex..<nl]
            buffer.removeSubrange(buffer.startIndex...nl)
            guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
            handle(obj)
        }
    }

    private func handle(_ e: [String: Any]) {
        switch e["ev"] as? String {
        case "status":
            switch e["state"] as? String {
            case "unlocked":
                state = .unlocked
                unlocking = false
                clear([.unlock])
                lockWatchdog?.cancel()
            case "locked":
                state = .locked
                unlocking = false
                keyCount = 0
                stale = false
                syncing = false
                clear([.refresh])
                lockWatchdog?.cancel()
            case "connecting":
                relayNote = e["detail"] as? String ?? "connecting to relay"
            case "listening":
                relayNote = nil
                // Only a core that reached the relay ends the backoff (#8).
                restartDelay = 1
            case "offline": state = .offline(e["detail"] as? String ?? "offline")
            default: break
            }
        case "token":
            token = e["token"] as? String
        case "windows":
            let items = e["items"] as? [[String: Any]] ?? []
            windows = items.compactMap { i in
                guard let id = i["id"] as? String, let secs = i["secs"] as? Double else { return nil }
                return AllowWindow(id: id, kind: i["kind"] as? String ?? "other", title: i["title"] as? String ?? "",
                                   sub: i["sub"] as? String ?? "", until: Date().addingTimeInterval(secs),
                                   total: max(1, i["total"] as? Double ?? secs))
            }
        case "keys":
            keyCount = e["count"] as? Int ?? 0
            switch e["problem"] as? String {
            case "offline": show("keys_offline")
            case "login": show("login")
            case nil: if keyCount == 0 { show("keys_none") } else if notice?.id.hasPrefix("keys_") == true { notice = nil }
            default: show("keys_failed")
            }
        case "syncing":
            syncing = true
        case "sync":
            syncing = false
            stale = !(e["ok"] as? Bool ?? true)
            if stale, let r = e["reason"] as? String {
                // Offline is the quiet line, not a card; a login problem needs you, so it's a card.
                if r == "login" { show("login") }
            } else if notice?.retry == .refresh, !(notice?.id.hasPrefix("keys_") ?? false) {
                notice = nil
            }
        case "notice":
            if let c = e["code"] as? String { show(c) }
        case "agents":
            func date(_ v: Any?) -> Date { Date(timeIntervalSince1970: v as? Double ?? 0) }
            let labels = Dictionary(paired.map { ($0.id, $0.label) }, uniquingKeysWith: { a, _ in a })
            tokens = (e["tokens"] as? [[String: Any]] ?? []).compactMap { t in
                guard let id = t["id"] as? String else { return nil }
                let last = (t["last_used"] as? Double).map { Date(timeIntervalSince1970: $0) }
                let device = (t["device"] as? String).map { labels[$0] ?? "Unnamed · \($0.prefix(6))" }
                return Agent(id: id, name: t["name"] as? String, since: date(t["created"]), seen: last, usedBy: device)
            }.sorted { ($0.seen ?? .distantPast, $0.since) > ($1.seen ?? .distantPast, $1.since) }
        case "request":
            guard let id = e["id"] as? Int else { return }
            let name = e["name"] as? String ?? "item"
            let domain = e["domain"] as? String
            var parts = [e["username"] as? String ?? "no username"]
            if let domain, domain.caseInsensitiveCompare(name) != .orderedSame { parts.append(domain) }
            if e["has_totp"] as? Bool ?? false { parts.append("+ 2FA code") }
            switch e["kind"] as? String {
            case "id": parts.append("by id")
            case "search": parts.append("by search")
            default: break
            }
            queue.append(CredRequest(
                id: id, title: name, detail: parts.joined(separator: "  ·  "),
                device: e["device"] as? String ?? "unknown",
                arrived: Date(), timeout: e["timeout"] as? Double ?? 110))
            announceArrival()
        case "ssh_request":
            guard let id = e["id"] as? Int else { return }
            let purpose = e["purpose"] as? String ?? "unverified data"
            let host = e["host"] as? String
            let user = e["user"] as? String
            let app = e["app"] as? String ?? "unknown program"
            let title = host.map { h in user.map { "\($0)@\(h)" } ?? h }
                ?? (purpose == "git signing" ? "Git commit" : "SSH signature")
            let key = e["key"] as? String ?? "SSH key"
            let via = (e["via"] as? [String])?.first
            // The hop goes first: the line is cut at the end when it's too long.
            let detail = (via.map { ["forwarded from \($0)"] } ?? []) + [key, purpose, app]
            queue.append(CredRequest(
                id: id, title: title, detail: detail.joined(separator: "  ·  "), device: app,
                arrived: Date(), timeout: e["timeout"] as? Double ?? 110,
                ssh: SSHInfo(key: key, purpose: purpose, app: app, via: via,
                             canRemember: e["can_allow"] as? Bool ?? false)))
            announceArrival()
        case "resolved":
            guard let id = e["id"] as? Int else { return }
            let label = queue.first(where: { $0.id == id })?.title
                ?? (e["domain"] as? String) ?? (e["query"] as? String) ?? ""
            queue.removeAll { $0.id == id }
            switch e["outcome"] as? String {
            case "approved": flash(.approved(label))
            case "denied": flash(.denied(label))
            case "auto": flash(.auto(label))
            case "expired": flash(.expired(label))
            case "not_found": flash(.notFound(label))
            case "locked": flash(.locked(label))
            case "cancelled": flash(.cancelled(label))
            default: break
            }
        default: break
        }
    }

    private let arrivalSound: NSSound? = {
        let s = NSSound(named: "Funk")
        s?.volume = 1.0
        return s
    }()

    /// Haptic plus a short system sound; `NSSound.play()` is asynchronous.
    private func announceArrival() {
        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .now)
        arrivalSound?.stop()
        arrivalSound?.play()
    }

    private func flash(_ o: Outcome) {
        outcomeWork?.cancel()
        outcome = o
        let w = DispatchWorkItem { [weak self] in self?.outcome = nil }
        outcomeWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0, execute: w)
    }

    func decide(_ r: CredRequest, _ decision: String, minutes: Int? = nil) {
        var obj: [String: Any] = ["op": "decide", "id": r.id, "decision": decision]
        if let minutes { obj["minutes"] = minutes }
        send(obj)
    }

    /// Touch ID via Bitwarden Desktop. Tries the official `bw unlock` first, then `bwbio`.
    /// The session goes straight into aac-core's stdin; never argv, env, or disk here.
    func unlock() {
        guard !unlocking else { return }
        guard let node = Tools.node, Tools.bw != nil || Tools.bwbio != nil else {
            show("tools_missing")
            return
        }
        unlocking = true
        let started = lockCount
        let candidates = [Tools.bw, Tools.bwbio].compactMap { $0 }
        DispatchQueue.global().async { [weak self] in
            var session: String?
            var why = "touchid_cancelled"
            for tool in candidates where session == nil {
                (session, why) = Core.touchIDSession(node: node, script: tool, fallback: why)
            }
            DispatchQueue.main.async {
                guard let self else { return }
                guard let session else {
                    self.unlocking = false
                    self.show(why)
                    return
                }
                guard started == self.lockCount else {
                    // The Mac slept or locked while Bitwarden's Touch ID prompt was up. Don't unlock
                    // behind a locked screen; lock again so the session just made stops working.
                    self.unlocking = false
                    self.send(["op": "lock"])
                    return
                }
                self.send(["op": "unlock", "session": session])
                // The core still runs `bw status` and loads the keys; stay "unlocking" until it
                // answers, so the button can't raise a second Bitwarden prompt meanwhile (#12).
                DispatchQueue.main.asyncAfter(deadline: .now() + 45) { [weak self] in
                    guard let self, self.state != .unlocked else { return }
                    self.unlocking = false
                }
            }
        }
    }

    /// Runs `<tool> unlock --raw` with no terminal and a 60 s limit (#18). With no Touch ID
    /// path, `bw` asks for a password, reads EOF from /dev/null and prints nothing. Returns the
    /// session, or why there is none as a notice code (`fallback` when stderr says nothing).
    static func touchIDSession(node: String, script: String, fallback: String) -> (String?, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: node)
        p.arguments = ["--unhandled-rejections=warn", script, "unlock", "--raw"]
        p.environment = ["HOME": NSHomeDirectory(), "PATH": Tools.childPath]
        let out = Pipe(), err = Pipe()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = out
        p.standardError = err
        guard (try? p.run()) != nil else { return (nil, fallback) }
        let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 60, execute: killer)
        var errData = Data()
        let errDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            errData = err.fileHandleForReading.readDataToEndOfFile()
            errDone.signal()
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        errDone.wait()
        p.waitUntilExit()
        killer.cancel()
        let s = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        // A bw session key is 64 random bytes, base64: 88 characters.
        if s.count == 88 && Data(base64Encoded: s) != nil { return (s, fallback) }
        return (nil, unlockFailure(String(decoding: errData, as: UTF8.self), fallback: fallback))
    }

    /// Why an unlock gave no session, from the tool's stderr. Only the code leaves here.
    static func unlockFailure(_ stderr: String, fallback: String) -> String {
        let s = stderr.lowercased()
        let any = { (w: [String]) in w.contains { s.contains($0) } }
        if any(["failed to connect to desktop", "not connected to desktop", "disconnected from desktop",
                "timed out waiting for desktop", "connection to desktop app timed out", "notenabledinconnecteddesktopapp"]) {
            return "desktop_unreachable"
        }
        if any(["no user id available", "account mismatch", "not logged in", "invalid_grant"]) { return "login" }
        if any(["denied or failed", "cancel"]) { return "touchid_cancelled" }
        return fallback
    }

    /// Counts locks, so an unlock that was still waiting when the Mac locked is dropped.
    private var lockCount = 0

    func lock() {
        lockCount += 1
        send(["op": "lock"])
        guard state == .unlocked else { return }
        lockWatchdog?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let self, self.state == .unlocked else { return }
            // The core didn't confirm within 3 s: it's stuck. The session and keys live only in
            // its memory, so ending it is a lock; then lock bw from here too.
            self.show("core_restarted")
            self.proc?.terminate()
            self.state = .locked
            DispatchQueue.global().async { Core.bwLock() }
        }
        lockWatchdog = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: w)
    }
    private var lockWatchdog: DispatchWorkItem?

    /// Asks the core for a new reusable pairing token, shown once (#27).
    func newToken(name: String? = nil) {
        var obj: [String: Any] = ["op": "new_token"]
        if let name, !name.isEmpty { obj["name"] = name }
        send(obj)
    }

    /// Ends these Allow windows, or every one (#5).
    func endWindows(_ ids: [String]? = nil) {
        var obj: [String: Any] = ["op": "end_windows"]
        if let ids { obj["ids"] = ids }
        send(obj)
    }

    func loadAgents() { send(["op": "agents"]) }
    /// Agent connections drop for about 2 s while the relay client restarts (#3).
    func removeDevice(_ id: String) { send(["op": "remove_device", "id": id]) }
    func removeToken(_ id: String) { send(["op": "remove_token", "id": id]) }
    func revokeAll() { send(["op": "revoke_all"]) }
    func rename(_ a: Agent, device: Bool, to name: String) {
        send(["op": device ? "rename_device" : "rename_token", "id": a.id, "name": name])
    }

    /// One place for what the panel tells you (#23).
    func show(_ code: String) { notice = Notice.of(code) }

    /// Clears a notice that this success resolves: one whose retry is one of `kinds`.
    func clear(_ kinds: [Notice.Retry]) {
        if let r = notice?.retry, kinds.contains(r) { notice = nil }
    }

    /// Sync again and reload the SSH keys.
    func refresh() { send(["op": "refresh"]) }
}

// MARK: - Presence check

/// Touch ID only (#5). This policy accepts neither the login password nor an Apple Watch
/// (the watch would need `.deviceOwnerAuthenticationWithBiometricsOrWatch`).
/// A script with Accessibility access can click and type, but cannot touch the sensor.
/// The caller creates the context first so it can recognise this exact prompt later (#7).
func confirmPresence(_ ctx: LAContext, _ reason: String, _ done: @escaping (Bool, String?) -> Void) {
    ctx.localizedFallbackTitle = ""
    var error: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        DispatchQueue.main.async { done(false, unavailableReason(error)) }
        return
    }
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, _ in
        DispatchQueue.main.async { done(ok, nil) }
    }
}

/// Why Touch ID can't run right now, in words (#28). Without it nothing can be approved.
func unavailableReason(_ error: NSError?) -> String {
    switch LAError.Code(rawValue: error?.code ?? 0) {
    case .biometryLockout: return "Touch ID is locked after failed tries. Unlock your Mac with its password, then try again."
    case .biometryNotEnrolled: return "No fingerprint is set up. Add one in System Settings → Touch ID & Password."
    case .biometryNotAvailable: return "Touch ID isn't available (lid closed or no sensor). Open the lid to approve."
    default: return "Touch ID isn't available right now."
    }
}
