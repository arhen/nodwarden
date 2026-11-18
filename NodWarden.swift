import AppKit
import LocalAuthentication
import SwiftUI

// MARK: - Core bridge

struct CredRequest: Identifiable, Equatable {
    let id: Int
    let domain: String
    let username: String?
    let device: String
    let hasTotp: Bool
    let byId: Bool
    let arrived: Date
    let timeout: Double
    /// Set for SSH agent requests: key name, purpose, and calling program.
    var ssh: SSHInfo? = nil
}

struct SSHInfo: Equatable {
    let key: String
    let purpose: String
    let app: String
}

/// The program behind a request: the nearest named ancestor that isn't a shell.
func requestingApp(_ chain: [String]) -> String {
    let skip: Set<String> = ["ssh", "ssh-keygen", "git", "git-remote-https", "bash", "zsh", "sh", "fish", "login", "sudo", "env", "xargs"]
    return chain.first { !skip.contains($0) } ?? chain.first ?? "unknown app"
}

enum VaultState: Equatable { case starting, locked, unlocked, offline(String) }

enum Outcome: Equatable {
    case approved(String), denied(String), auto(String), expired(String), notFound(String), locked(String)
}

/// launchd starts apps with a bare PATH. `bw` and `bwbio` are Node scripts, so
/// node must be findable too. Set NODWARDEN_PATH to override.
let toolPath: String = ProcessInfo.processInfo.environment["NODWARDEN_PATH"] ?? [
    "\(NSHomeDirectory())/.n/bin", "\(NSHomeDirectory())/.volta/bin", "\(NSHomeDirectory())/.local/bin",
    "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
].joined(separator: ":")

final class Core: ObservableObject {
    @Published var state: VaultState = .starting
    @Published var queue: [CredRequest] = []
    @Published var outcome: Outcome?
    @Published var unlocking = false

    private var proc: Process?
    private var stdin: FileHandle?
    private var buffer = Data()
    private var outcomeWork: DispatchWorkItem?

    var corePath: String {
        Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("aac-core").path
    }

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: corePath)
        // launchd gives a bare PATH; bw is a `#!/usr/bin/env node` script and needs node.
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = toolPath
        p.environment = env
        let inPipe = Pipe(), outPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = outPipe
        p.standardError = FileHandle(forWritingAtPath: "/tmp/aac-core.log") ?? FileHandle.nullDevice
        outPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            DispatchQueue.main.async { self?.ingest(d) }
        }
        p.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                self?.state = .offline("listener stopped")
                self?.queue.removeAll()
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self?.start() }
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
        // Wipe the session-encrypted user key bwbio left in bw's data.json.
        let lock = Process()
        lock.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        lock.arguments = ["bw", "lock"]
        lock.environment = ["PATH": toolPath]
        try? lock.run()
        lock.waitUntilExit()
    }

    private func send(_ obj: [String: Any]) {
        guard let stdin, let d = try? JSONSerialization.data(withJSONObject: obj) else { return }
        stdin.write(d + Data([0x0A]))
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
            case "unlocked": state = .unlocked
            case "locked": state = .locked
            case "offline": state = .offline(e["detail"] as? String ?? "offline")
            default: break
            }
        case "request":
            guard let id = e["id"] as? Int else { return }
            let q = e["query"] as? String ?? "?"
            let r = CredRequest(
                id: id,
                domain: (e["domain"] as? String) ?? q,
                username: e["username"] as? String,
                device: e["device"] as? String ?? "unknown",
                hasTotp: e["has_totp"] as? Bool ?? false,
                byId: (e["kind"] as? String) == "id",
                arrived: Date(),
                timeout: e["timeout"] as? Double ?? 110
            )
            queue.append(r)
            NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .now)
        case "ssh_request":
            guard let id = e["id"] as? Int else { return }
            let chain = e["process"] as? [String] ?? []
            let purpose = e["purpose"] as? String ?? "signing"
            let r = CredRequest(
                id: id,
                domain: (e["host"] as? String) ?? (purpose == "git signing" ? "Git commit" : "SSH"),
                username: nil,
                device: "",
                hasTotp: false,
                byId: false,
                arrived: Date(),
                timeout: e["timeout"] as? Double ?? 110,
                ssh: SSHInfo(key: e["key"] as? String ?? "SSH key", purpose: purpose, app: requestingApp(chain))
            )
            queue.append(r)
            NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .now)
        case "resolved":
            guard let id = e["id"] as? Int else { return }
            let label = queue.first(where: { $0.id == id })?.domain
                ?? (e["domain"] as? String) ?? (e["query"] as? String) ?? ""
            queue.removeAll { $0.id == id }
            switch e["outcome"] as? String {
            case "approved": flash(.approved(label))
            case "denied": flash(.denied(label))
            case "auto": flash(.auto(label))
            case "expired": flash(.expired(label))
            case "not_found": flash(.notFound(label))
            case "locked": flash(.locked(label))
            default: break
            }
        default: break
        }
    }

    private func flash(_ o: Outcome) {
        outcomeWork?.cancel()
        outcome = o
        let w = DispatchWorkItem { [weak self] in self?.outcome = nil }
        outcomeWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6, execute: w)
    }

    func decide(_ r: CredRequest, _ decision: String, minutes: Int? = nil) {
        var obj: [String: Any] = ["op": "decide", "id": r.id, "decision": decision]
        if let minutes { obj["minutes"] = minutes }
        send(obj)
    }

    /// Touch ID via Bitwarden Desktop. Tries the official `bw unlock` first (bw >= 2026.10
    /// with the server's `biometrics-sdk-ipc` flag on), then `bwbio`. The session goes
    /// straight into the listener's stdin; it never touches argv, env, or disk here.
    func unlock() {
        guard !unlocking else { return }
        unlocking = true
        DispatchQueue.global().async {
            let session = Core.touchIDSession(["bw", "unlock", "--raw"])
                ?? Core.touchIDSession(["bwbio", "unlock", "--raw"])
            DispatchQueue.main.async {
                self.unlocking = false
                if let session { self.send(["op": "unlock", "session": session]) }
            }
        }
    }

    /// Runs an unlock command with no terminal. With no Touch ID path, `bw` falls back to a
    /// password prompt, reads EOF from /dev/null and prints nothing, so this returns nil.
    static func touchIDSession(_ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = args
        p.environment = ["PATH": toolPath, "HOME": NSHomeDirectory()]
        let out = Pipe()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let s = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        // A bw session key is 64 random bytes, base64: 88 characters.
        return s.count == 88 && Data(base64Encoded: s) != nil ? s : nil
    }

    func lock() { send(["op": "lock"]) }
}

// MARK: - Presence check

/// Approving with a click alone could be forged by anything with Accessibility
/// access. Device-owner auth means the release needs a finger, not a mouse event.
/// Returns the context so the caller can cancel a pending prompt (Deny, Allow 10m, timeout).
@discardableResult
func confirmPresence(_ reason: String, _ done: @escaping (Bool) -> Void) -> LAContext {
    let ctx = LAContext()
    ctx.localizedFallbackTitle = ""
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
        DispatchQueue.main.async { done(ok) }
    }
    return ctx
}

// MARK: - Geometry

struct Notch {
    let width: CGFloat
    let height: CGFloat
    static var current: Notch {
        guard let s = NSScreen.screens.first(where: { $0.safeAreaInsets.top > 0 }) ?? NSScreen.main else {
            return Notch(width: 0, height: 28)
        }
        let l = s.auxiliaryTopLeftArea?.width ?? 0
        let r = s.auxiliaryTopRightArea?.width ?? 0
        if s.safeAreaInsets.top > 0, l > 0, r > 0 {
            return Notch(width: s.frame.width - l - r, height: s.safeAreaInsets.top)
        }
        // No notch (older MacBooks, external displays): a pill hanging from the menu bar.
        let menuBar = s.frame.maxY - s.visibleFrame.maxY
        return Notch(width: 0, height: max(24, menuBar))
    }
}

enum Mode: Equatable { case hidden, compact, expanded }

/// Notch-fused silhouette: flush top edge, small concave shoulders where it
/// meets the bezel, large continuous corners at the bottom.
struct IslandShape: Shape {
    var top: CGFloat
    var bottom: CGFloat
    var animatableData: AnimatablePair<CGFloat, CGFloat> {
        get { AnimatablePair(top, bottom) }
        set { top = newValue.first; bottom = newValue.second }
    }

    func path(in r: CGRect) -> Path {
        var p = Path()
        let t = min(top, r.width / 4), b = min(bottom, r.height / 2, r.width / 2 - t)
        p.move(to: CGPoint(x: r.minX, y: r.minY))
        p.addQuadCurve(to: CGPoint(x: r.minX + t, y: r.minY + t), control: CGPoint(x: r.minX + t, y: r.minY))
        p.addLine(to: CGPoint(x: r.minX + t, y: r.maxY - b))
        p.addQuadCurve(to: CGPoint(x: r.minX + t + b, y: r.maxY), control: CGPoint(x: r.minX + t, y: r.maxY))
        p.addLine(to: CGPoint(x: r.maxX - t - b, y: r.maxY))
        p.addQuadCurve(to: CGPoint(x: r.maxX - t, y: r.maxY - b), control: CGPoint(x: r.maxX - t, y: r.maxY))
        p.addLine(to: CGPoint(x: r.maxX - t, y: r.minY + t))
        p.addQuadCurve(to: CGPoint(x: r.maxX, y: r.minY), control: CGPoint(x: r.maxX - t, y: r.minY))
        p.closeSubpath()
        return p
    }
}

// MARK: - Views

let springOpen = Animation.spring(response: 0.42, dampingFraction: 0.8)
let springClose = Animation.spring(response: 0.34, dampingFraction: 1.0)
/// Small content swaps (icon ↔ label, status changes): quick, no overshoot.
let springSwap = Animation.spring(response: 0.28, dampingFraction: 0.9)

/// Blurs and scales while fading, so a swap reads as one element morphing.
struct BlurScale: ViewModifier {
    let on: Bool
    var scale: CGFloat = 0.8
    var y: CGFloat = 0
    func body(content: Content) -> some View {
        content
            .blur(radius: on ? 0 : 5)
            .scaleEffect(on ? 1 : scale)
            .opacity(on ? 1 : 0)
            .offset(y: on ? 0 : y)
    }
}

extension AnyTransition {
    static func blurSwap(y: CGFloat = 0) -> AnyTransition {
        .modifier(active: BlurScale(on: false, scale: 0.85, y: y), identity: BlurScale(on: true))
    }
}

final class Layout: ObservableObject {
    var size: CGSize = .zero
    /// Set by the panel: a click landed outside the island, or Esc was pressed.
    @Published var dismissTick = 0
}

struct IslandView: View {
    @ObservedObject var core: Core
    @ObservedObject var layout: Layout
    @State private var hovering: Bool
    @State private var pinned: Bool
    @State private var minutes = 10
    @State private var confirming = false
    /// The Touch ID prompt for the request on screen, started as soon as it arrives.
    @State private var prompt: (id: Int, ctx: LAContext)?
    /// Request whose Touch ID just succeeded; drives the red fill.
    @State private var granted: Int?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let notch = Notch.current

    init(core: Core, layout: Layout, hoveringInitial: Bool = false, pinnedInitial: Bool = false, grantedInitial: Int? = nil, confirmingInitial: Bool = false) {
        self.core = core
        self.layout = layout
        _hovering = State(initialValue: hoveringInitial)
        _pinned = State(initialValue: pinnedInitial)
        _granted = State(initialValue: grantedInitial)
        _confirming = State(initialValue: confirmingInitial)
    }

    var current: CredRequest? { core.queue.first }

    var mode: Mode {
        if current != nil || pinned { return .expanded }
        return .compact
    }

    /// Width of each "ear" flanking the notch. Always visible so the island
    /// reads as present even on a static hardware notch.
    var ear: CGFloat {
        if core.outcome != nil { return 96 }
        return hovering ? 78 : 64
    }

    var size: CGSize {
        switch mode {
        case .hidden: return CGSize(width: notch.width, height: notch.height)
        case .compact: return CGSize(width: max(notch.width, 120) + ear * 2, height: notch.height)
        case .expanded:
            return CGSize(width: max(notch.width + 200, 440), height: notch.height + (current != nil ? 106 : 104))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            ZStack(alignment: .top) {
                IslandShape(top: mode == .hidden ? 6 : 8, bottom: mode == .expanded ? 30 : 12)
                    .fill(.black)
                    .shadow(color: .black.opacity(mode == .expanded ? 0.45 : 0), radius: 18, y: 8)

                content
                    .foregroundStyle(.white)
                    .padding(.horizontal, 8 + 14)
            }
            .frame(width: size.width, height: size.height)
            .contentShape(Rectangle())
            .onHover { h in
                withAnimation(h ? springOpen : springClose) { hovering = h }
                if !h, pinned { collapseSoon() }
            }
            .onTapGesture {
                guard current == nil else { return }
                withAnimation(pinned ? springClose : springOpen) { pinned.toggle() }
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .animation(reduceMotion ? .easeOut(duration: 0.18) : (mode == .hidden ? springClose : springOpen), value: mode)
        .animation(reduceMotion ? .easeOut(duration: 0.18) : springOpen, value: current?.id)
        .environment(\.colorScheme, .dark)
        .onAppear { layout.size = size }
        .onChange(of: size) { _, s in layout.size = s }
        .onChange(of: layout.dismissTick) { _, _ in
            if pinned { withAnimation(springClose) { pinned = false } }
        }
        .onChange(of: current?.id) { _, id in
            cancelPrompt()
            if let id, let r = core.queue.first(where: { $0.id == id }) { approve(r, minutes: nil) }
        }
    }

    func cancelPrompt() {
        prompt?.ctx.invalidate()
        prompt = nil
        confirming = false
        granted = nil
    }

    /// Status panel folds back once the pointer has been away for a moment.
    func collapseSoon() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            if !hovering, pinned { withAnimation(springClose) { pinned = false } }
        }
    }

    @ViewBuilder var content: some View {
        switch mode {
        case .hidden:
            EmptyView()
        case .compact:
            compact.frame(height: notch.height)
        case .expanded:
            if let r = current { requestView(r) } else { statusView }
        }
    }

    // Leading and trailing "ears" that flank the hardware notch.
    var compact: some View {
        HStack(spacing: 6) {
            leadingGlyph.font(.system(size: 14, weight: .semibold))
            if notch.width == 0 { trailingGlyph }
            Spacer(minLength: 0)
            if notch.width > 0 { trailingGlyph }
        }
        .transition(.opacity.combined(with: .scale(scale: 0.9)))
    }

    /// The brand mark always holds the left ear; state lives on the right.
    var leadingGlyph: some View {
        Mark(size: 18)
            .opacity(core.state == .unlocked ? 1 : 0.55)
            .symbolEffect(.pulse, isActive: core.unlocking)
            .accessibilityLabel("NodWarden, \(stateLabel)")
    }

    /// Identity for the right ear's content, so each change gets its own transition.
    var trailingKey: String {
        switch core.outcome {
        case .approved(let d), .auto(let d): return "ok:\(d)"
        case .denied: return "denied"
        case .expired: return "expired"
        case .notFound: return "notfound"
        case .locked: return "lockedout"
        case nil: return core.unlocking ? "unlocking" : "state"
        }
    }

    @ViewBuilder var trailingGlyph: some View {
        ZStack {
            trailingContent
                .id(trailingKey)
                .transition(reduceMotion ? .opacity : .blurSwap(y: 4))
        }
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: trailingKey)
    }

    @ViewBuilder var trailingContent: some View {
        Group {
            switch core.outcome {
            case .approved(let d): Label(short(d), systemImage: "checkmark").foregroundStyle(.green)
            case .auto(let d): Label(short(d), systemImage: "checkmark").foregroundStyle(.green)
            case .denied: Label("Denied", systemImage: "xmark").foregroundStyle(.red)
            case .expired: Label("Timed out", systemImage: "xmark").foregroundStyle(.red)
            case .notFound: Text("No match").foregroundStyle(.orange)
            case .locked: Text("Locked")
            case nil:
                if core.unlocking {
                    Image(systemName: "touchid").font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.pink).symbolEffect(.pulse)
                } else {
                    Image(systemName: lockSymbol)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(stateColor)
                        .contentTransition(.symbolEffect(.replace.magic(fallback: .downUp.byLayer)))
                        .animation(springSwap, value: lockSymbol)
                }
            }
        }
        .font(.system(size: 12, weight: .semibold))
        .foregroundStyle(.white.opacity(0.85))
        .lineLimit(1)
    }

    func requestView(_ r: CredRequest) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                if r.ssh != nil {
                    ZStack {
                        RoundedRectangle(cornerRadius: 9, style: .continuous).fill(.white.opacity(0.12))
                        Image(systemName: r.ssh?.purpose == "git signing" ? "signature" : "terminal.fill")
                            .font(.system(size: 16, weight: .semibold))
                    }
                    .frame(width: 36, height: 36)
                } else {
                    Favicon(domain: r.domain)
                }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(r.domain).font(.system(size: 15, weight: .semibold)).lineLimit(1)
                        if core.queue.count > 1 {
                            Text("+\(core.queue.count - 1)")
                                .font(.system(size: 11, weight: .bold))
                                .contentTransition(.numericText(value: Double(core.queue.count)))
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background(.white.opacity(0.14), in: Capsule())
                                .transition(.blurSwap())
                        }
                    }
                    Text(detailLine(r))
                        .font(.system(size: 12))
                        .foregroundStyle(.white.opacity(0.6))
                        .lineLimit(1)
                }
                Spacer(minLength: 8)
                Countdown(start: r.arrived, total: r.timeout).id(r.id)
            }

            HStack(spacing: 8) {
                Button("Deny") { cancelPrompt(); core.decide(r, "deny") }.buttonStyle(Pill(.quiet))
                Spacer(minLength: 0)
                HStack(spacing: 0) {
                    Button { cancelPrompt(); approve(r, minutes: minutes) } label: {
                        HStack(spacing: 4) {
                            Text("Allow")
                            Text("\(minutes)m").contentTransition(.numericText(value: Double(minutes)))
                        }
                    }
                        .buttonStyle(Pill(.quiet, flat: true))
                        .accessibilityLabel("Allow for \(minutes) minutes")
                    Button {
                        let steps = [5, 10, 30, 60]
                        withAnimation(springSwap) {
                            minutes = steps[((steps.firstIndex(of: minutes) ?? 1) + 1) % steps.count]
                        }
                    } label: {
                        Image(systemName: "chevron.up.chevron.down").font(.system(size: 10, weight: .bold))
                    }
                    .buttonStyle(Pill(.quiet, flat: true, compact: true))
                    .accessibilityLabel("Change auto-allow duration")
                }
                .background(.white.opacity(0.14), in: Capsule())
                AllowButton(waiting: confirming, filled: granted == r.id) { approve(r, minutes: nil) }
            }
        }
        .padding(.top, notch.height + 10)
        .padding(.bottom, 16)
        .transition(.asymmetric(
            insertion: .opacity.combined(with: .offset(y: -6)).animation(springOpen.delay(0.06)),
            removal: .opacity.animation(.easeOut(duration: 0.12))
        ))
    }

    var statusView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Mark(size: 30)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Image(systemName: lockSymbol).font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(stateColor)
                            .contentTransition(.symbolEffect(.replace.magic(fallback: .downUp.byLayer)))
                        Text(stateLabel).font(.system(size: 14, weight: .semibold))
                            .contentTransition(.interpolate)
                    }
                    Text(stateDetail).font(.system(size: 12)).foregroundStyle(.white.opacity(0.6))
                        .contentTransition(.interpolate)
                }
                Spacer()
            }
            HStack {
                Spacer()
                ZStack {
                    switch core.state {
                    case .unlocked:
                        Button("Lock") { core.lock() }.buttonStyle(Pill(.quiet))
                            .transition(.blurSwap(y: 6))
                    case .locked:
                        Button(core.unlocking ? "Waiting for Touch ID…" : "Unlock with Touch ID") { core.unlock() }
                            .buttonStyle(Pill(.primary))
                            .transition(.blurSwap(y: 6))
                    default:
                        EmptyView()
                    }
                }
            }
        }
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: core.state)
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: core.unlocking)
        .padding(.top, notch.height + 10)
        .padding(.bottom, 16)
        .transition(.opacity.animation(springOpen.delay(0.06)))
    }

    func approve(_ r: CredRequest, minutes m: Int?) {
        guard !confirming else { return }
        confirming = true
        let what: String
        if let s = r.ssh {
            let target = s.purpose == "git signing" ? "sign a git commit" : "use \(s.key) for \(r.domain)"
            what = m.map { "let \(s.app) \(target) for \($0) minutes" } ?? "let \(s.app) \(target)"
        } else {
            what = m.map { "allow \(r.domain) for \(r.device) for \($0) minutes" } ?? "release \(r.domain) to \(r.device)"
        }
        let ctx = confirmPresence(what) { ok in
            // Ignore a stale answer: the request was decided or replaced meanwhile.
            guard prompt?.id == r.id else { return }
            prompt = nil
            confirming = false
            guard ok, core.queue.contains(where: { $0.id == r.id }) else { return }
            if let m {
                minutes = m
                core.decide(r, "approve_for", minutes: m)
                return
            }
            // Let the red fill finish, then release.
            granted = r.id
            NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .now)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) {
                guard core.queue.contains(where: { $0.id == r.id }) else { return }
                core.decide(r, "approve")
            }
        }
        prompt = (r.id, ctx)
    }

    func detailLine(_ r: CredRequest) -> String {
        if let s = r.ssh { return "\(s.key)  ·  \(s.purpose)  ·  \(s.app)" }
        var parts = [r.username ?? "no username"]
        if r.hasTotp { parts.append("+ 2FA") }
        parts.append("→ \(r.device)")
        return parts.joined(separator: "  ")
    }

    func short(_ d: String) -> String { d.count > 18 ? String(d.prefix(17)) + "…" : d }

    var lockSymbol: String {
        switch core.state {
        case .unlocked: return "lock.open.fill"
        case .offline: return "wifi.exclamationmark"
        default: return "lock.fill"
        }
    }

    var stateColor: Color {
        switch core.state {
        case .unlocked: return .green
        case .locked: return .red
        case .offline: return .orange
        case .starting: return .white.opacity(0.7)
        }
    }

    var stateLabel: String {
        switch core.state {
        case .unlocked: return "Unlocked"
        case .locked: return "Locked"
        case .starting: return "Starting"
        case .offline: return "Offline"
        }
    }

    var stateDetail: String {
        switch core.state {
        case .unlocked: return "Vault unlocked · requests need your approval"
        case .locked: return "Vault locked · agent requests are denied"
        case .starting: return "Connecting to relay…"
        case .offline(let why): return why
        }
    }
}

/// The NodWarden mark (fingerprint into key), drawn as a template image so it
/// takes the surrounding color. Loaded from the bundle; falls back to an SF Symbol.
struct Mark: View {
    let size: CGFloat
    static let image: NSImage? = {
        let beside = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("mark.png")
        guard let url = Bundle.main.url(forResource: "mark", withExtension: "png") ?? beside,
              let img = NSImage(contentsOf: url) else { return nil }
        img.isTemplate = true
        return img
    }()
    var body: some View {
        Group {
            if let img = Mark.image {
                Image(nsImage: img).resizable().interpolation(.high).scaledToFit()
            } else {
                Image(systemName: "touchid").resizable().scaledToFit()
            }
        }
        .frame(width: size, height: size)
    }
}

struct Favicon: View {
    let domain: String
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 9, style: .continuous).fill(.white.opacity(0.12))
            Text(domain.first.map { String($0).uppercased() } ?? "?")
                .font(.system(size: 17, weight: .bold, design: .rounded))
        }
        .frame(width: 36, height: 36)
        .overlay(
            AsyncImage(url: URL(string: "https://icons.duckduckgo.com/ip3/\(domain).ico")) { img in
                img.resizable().interpolation(.high).scaledToFit().padding(7)
            } placeholder: { Color.clear }
        )
    }
}

struct Countdown: View {
    let start: Date
    let total: Double
    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.25)) { ctx in
            let left = max(0, total - ctx.date.timeIntervalSince(start))
            ZStack {
                Circle().stroke(.white.opacity(0.15), lineWidth: 2.5)
                Circle()
                    .trim(from: 0, to: left / total)
                    .stroke(left < 15 ? Color.orange : Color.white.opacity(0.75),
                            style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .animation(.linear(duration: 0.25), value: left)
                Text("\(Int(left.rounded(.up)))")
                    .font(.system(size: 10, weight: .semibold).monospacedDigit())
                    .foregroundStyle(left < 15 ? Color.orange : .white.opacity(0.7))
                    .contentTransition(.numericText(countsDown: true))
                    .animation(springSwap, value: Int(left.rounded(.up)))
            }
            .frame(width: 28, height: 28)
        }
    }
}

/// Fingerprint at rest (touching the sensor is the approval); "Allow" on hover for clicking.
/// On success the print fills red from the bottom before the secret is released.
/// macOS reports only the result of Touch ID, not finger-down, so the fill plays on success.
struct AllowButton: View {
    let waiting: Bool
    let filled: Bool
    let action: () -> Void
    @State private var hover = false

    /// After Touch ID is cancelled (`waiting` false), it's a plain "Allow" button that reopens it.
    var showText: Bool { (hover || !waiting) && !filled }

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: action) {
            ZStack {
                fingerprint
                    .modifier(BlurScale(on: !showText, scale: 0.6, y: -6))
                    .scaleEffect(filled ? 1.15 : 1)
                Text("Allow")
                    .modifier(BlurScale(on: showText, scale: 0.7, y: 6))
            }
            // Same width for both, so the button never jumps.
            .frame(width: 44)
        }
        .buttonStyle(Pill(.primary))
        .disabled(filled)
        .onHover { h in withAnimation(reduceMotion ? .easeOut(duration: 0.12) : springSwap) { hover = h } }
        .animation(reduceMotion ? .easeOut(duration: 0.12) : springSwap, value: waiting)
        .animation(.spring(response: 0.3, dampingFraction: 0.6), value: filled)
        .help(waiting ? "Touch the sensor, or click to allow" : "Allow")
        .accessibilityLabel("Allow")
    }

    var glyph: some View {
        Image(systemName: "touchid").font(.system(size: 17, weight: .semibold))
    }

    var fingerprint: some View {
        glyph
            .symbolEffect(.pulse, isActive: waiting && !hover && !filled)
            .overlay {
                GeometryReader { g in
                    Rectangle()
                        .fill(Color(red: 1, green: 0.23, blue: 0.3))
                        .frame(height: g.size.height * (filled ? 1 : 0))
                        .frame(maxHeight: .infinity, alignment: .bottom)
                        .animation(.easeOut(duration: 0.4), value: filled)
                }
                .mask(glyph)
            }
    }
}

struct Pill: ButtonStyle {
    enum Kind { case primary, quiet }
    let kind: Kind
    var flat = false
    var compact = false
    init(_ kind: Kind, flat: Bool = false, compact: Bool = false) {
        self.kind = kind; self.flat = flat; self.compact = compact
    }

    func makeBody(configuration c: Configuration) -> some View {
        c.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(kind == .primary ? .black : .white)
            .padding(.leading, compact ? 4 : 16)
            .padding(.trailing, compact ? 12 : (flat ? 6 : 16))
            .frame(height: 30)
            .background(flat ? Color.clear : (kind == .primary ? Color.white : Color.white.opacity(0.14)), in: Capsule())
            .opacity(c.isPressed ? 0.8 : 1)
            .scaleEffect(c.isPressed ? 0.96 : 1)
            .animation(.easeOut(duration: 0.1), value: c.isPressed)
            .contentShape(Capsule())
    }
}

// MARK: - Window

final class IslandPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let core = Core()
    let layout = Layout()
    var panel: IslandPanel!
    var sigterm: DispatchSourceSignal?

    func applicationDidFinishLaunching(_ n: Notification) {
        let frameW: CGFloat = 640, frameH: CGFloat = 260
        panel = IslandPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.level = .statusBar + 1
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = false
        panel.isMovable = false
        panel.hidesOnDeactivate = false
        panel.contentView = NSHostingView(rootView: IslandView(core: core, layout: layout))
        place(w: frameW, h: frameH)
        panel.orderFrontRegardless()
        panel.ignoresMouseEvents = false
        NotificationCenter.default.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main) { [weak self] _ in
            self?.place(w: frameW, h: frameH)
        }
        trackClickThrough()
        let dismiss: (NSEvent) -> Void = { [weak self] _ in self?.layout.dismissTick += 1 }
        NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown], handler: dismiss)
        NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] e in
            if e.keyCode == 53 { self?.layout.dismissTick += 1 }
            return e
        }
        signal(SIGTERM, SIG_IGN)
        sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigterm?.setEventHandler { NSApp.terminate(nil) }
        sigterm?.resume()
        core.start()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            if self?.core.state == .locked { self?.core.unlock() }
        }
    }

    func place(w: CGFloat, h: CGFloat) {
        guard let s = NSScreen.screens.first(where: { $0.safeAreaInsets.top > 0 }) ?? NSScreen.main else { return }
        panel.setFrame(NSRect(x: s.frame.midX - w / 2, y: s.frame.maxY - h, width: w, height: h), display: true)
    }

    /// The panel is larger than the island; let clicks outside the island fall
    /// through to whatever is underneath (the menu bar, other windows).
    func trackClickThrough() {
        Timer.scheduledTimer(withTimeInterval: 1.0 / 30, repeats: true) { [weak self] _ in
            guard let self else { return }
            let f = self.panel.frame, s = self.layout.size
            let island = NSRect(x: f.midX - s.width / 2, y: f.maxY - s.height, width: s.width, height: s.height)
            let over = island.insetBy(dx: -4, dy: -4).contains(NSEvent.mouseLocation)
            if self.panel.ignoresMouseEvents == over { self.panel.ignoresMouseEvents = !over }
        }
    }

    func applicationWillTerminate(_ n: Notification) { core.stop() }
}

// Renders each state to PNG with fake data: `nodwarden --snapshot <dir>`.
@MainActor
func snapshot(to dir: String) {
    let sample = CredRequest(id: 1, domain: "github.com", username: "octocat", device: "a1b2c3d4e5f6",
                             hasTotp: true, byId: true, arrived: Date(), timeout: 110)
    func shot(_ name: String, _ hover: Bool = false, _ pinned: Bool = false, granted: Int? = nil, waiting: Bool = false, _ setup: (Core) -> Void) {
        let core = Core()
        setup(core)
        let v = IslandView(core: core, layout: Layout(), hoveringInitial: hover, pinnedInitial: pinned, grantedInitial: granted, confirmingInitial: waiting)
            .frame(width: 640, height: 190)
            .background(LinearGradient(colors: [Color(red: 0.16, green: 0.20, blue: 0.32), Color(red: 0.08, green: 0.09, blue: 0.14)],
                                       startPoint: .top, endPoint: .bottom))
        let r = ImageRenderer(content: v)
        r.scale = 2
        guard let img = r.nsImage, let tiff = img.tiffRepresentation,
              let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]) else { return }
        try? png.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
    }
    shot("1-idle") { $0.state = .unlocked }
    shot("1b-idle-locked") { $0.state = .locked }
    shot("2-hover", true) { $0.state = .unlocked }
    shot("3-request", waiting: true) { $0.state = .unlocked; $0.queue = [sample] }
    shot("3a-cancelled") { $0.state = .unlocked; $0.queue = [sample] }
    shot("3c-ssh", waiting: true) {
        $0.state = .unlocked
        $0.queue = [CredRequest(id: 2, domain: "github.com", username: nil, device: "", hasTotp: false, byId: false,
                                arrived: Date(), timeout: 110,
                                ssh: SSHInfo(key: "Personal Github Key", purpose: "login", app: "pi"))]
    }
    shot("3b-touched", granted: 1, waiting: true) { $0.state = .unlocked; $0.queue = [sample] }
    shot("4-queue") { $0.state = .unlocked; $0.queue = [sample, sample] }
    shot("5-approved") { $0.state = .unlocked; $0.outcome = .approved("github.com") }
    shot("6-denied") { $0.state = .unlocked; $0.outcome = .denied("github.com") }
    shot("7-locked-pinned", false, true) { $0.state = .locked }
    shot("8-unlocking") { $0.state = .locked; $0.unlocking = true }
    shot("9-offline") { $0.state = .offline("relay disconnected") }
}

@main
enum Main {
    static let delegate = AppDelegate()
    static func main() {
        if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count {
            MainActor.assumeIsolated { snapshot(to: CommandLine.arguments[i + 1]) }
            return
        }
        let app = NSApplication.shared
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
