import AppKit
import LocalAuthentication
import SwiftUI

// MARK: - Status panel: home, Agents, new token. Everything stays inside the notch.

enum Page: Equatable {
    case home, agents, history, newToken
    case confirm(Removal)
    case rename(Agent, device: Bool)
}

enum Removal: Equatable {
    case device(Agent), token(Agent), all
}

extension Core {
    var lockSymbol: String {
        switch state {
        case .unlocked: return "lock.open.fill"
        case .offline: return "wifi.exclamationmark"
        default: return "lock.fill"
        }
    }

    var stateColor: Color {
        switch state {
        case .unlocked: return .green
        case .locked: return .red
        case .offline: return .orange
        case .starting: return .white.opacity(0.7)
        }
    }

    var stateLabel: String {
        switch state {
        case .unlocked: return "Unlocked"
        case .locked: return "Locked"
        case .starting: return "Starting"
        case .offline: return "Offline"
        }
    }

    /// The panel header's line, and a dot only when something isn't normal. `lead` is plain,
    /// `note` is tinted: "Ready · relay connected", "Ready · offline copy".
    var headerStatus: (dot: Color?, lead: String, note: String?, tint: Color?, pulse: Bool) {
        switch state {
        case .starting: return (.white.opacity(0.45), "Starting…", nil, nil, false)
        case .offline: return (Tint.bad, "Stopped · restarting…", nil, nil, false)
        // While unlocking the button says "Waiting for Touch ID…"; the dot breathes.
        case .locked: return (Tint.bad, "Locked", nil, nil, unlocking)
        case .unlocked:
            if notice?.tone == .error { return (Tint.bad, "Needs attention", nil, Tint.bad, false) }
            if stale { return (Tint.warn, "Ready", syncing ? "syncing…" : "offline copy", Tint.warn, false) }
            if relayNote != nil { return (Tint.warn, "Ready", "agents paused, reconnecting", Tint.warn, false) }
            return (nil, "Ready", "relay connected", nil, false)
        }
    }
}

/// The text field needs keyboard focus, which a nonactivating panel only gets once it's key.
/// Giving it back (out and in again) matters: a key panel that folded away would keep
/// taking your typing.
@MainActor func islandPanel() -> NSWindow? { NSApp.windows.first { $0 is IslandPanel } }
@MainActor func releaseKeyboard() {
    guard let p = islandPanel(), p.isKeyWindow else { return }
    p.orderOut(nil)
    p.orderFrontRegardless()
}

struct PanelView: View {
    @ObservedObject var core: Core
    @Binding var page: Page
    @State private var name = ""
    @State private var createdName: String?
    @State private var creating = false
    @State private var removing = false
    /// The live Touch ID prompt for a removal; cancelled when you leave the confirm card.
    @State private var prompt: LAContext?
    @State private var problem: String?
    @FocusState private var nameFocused: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var key: String {
        if core.token != nil { return "created" }
        switch page {
        case .home: return "home"
        case .agents: return "agents"
        case .history: return "history"
        case .newToken: return "new"
        case .confirm: return "confirm"
        case .rename: return "rename"
        }
    }

    var body: some View {
        ZStack(alignment: .top) {
            Group {
                if core.token != nil {
                    tokenCreated
                } else {
                    switch page {
                    case .home: home
                    case .agents: agents
                    case .history: historyPage
                    case .newToken: newToken
                    case .confirm(let r): confirm(r)
                    case .rename(let a, let device): rename(a, device: device)
                    }
                }
            }
            .id(key)
            .transition(reduceMotion ? .opacity : .blurSwap(y: 6))
        }
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: key)
        .onChange(of: core.token) { _, t in if t != nil { creating = false } }
        .onChange(of: core.notice) { _, n in if n != nil { creating = false } }
    }

    func go(_ p: Page) {
        prompt?.invalidate()
        prompt = nil
        removing = false
        problem = nil
        page = p
    }

    // MARK: home

    var home: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Mark(size: 30).opacity(core.state == .unlocked ? 1 : 0.6)
                // One status line always; a dot only when something isn't normal.
                let st = core.headerStatus
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 7) {
                        Wordmark()
                        if let dot = st.dot {
                            StateDot(color: dot, pulse: st.pulse).transition(.scale.combined(with: .opacity))
                        }
                    }
                    HStack(spacing: 5) {
                        Group {
                            if let note = st.note {
                                Text("\(st.lead) · ").foregroundColor(.white.opacity(0.55))
                                    + Text(note).foregroundColor(st.tint ?? .white.opacity(0.55))
                            } else {
                                Text(st.lead).foregroundColor(st.tint ?? .white.opacity(0.55))
                            }
                        }
                        .contentTransition(.interpolate)
                        if core.state == .unlocked && core.stale && core.notice?.tone != .error {
                            // Retries by itself; the button is for not waiting.
                            SyncButton(spinning: core.syncing) { core.refresh() }
                        }
                    }
                    .font(.system(size: 12))
                    .lineLimit(1)
                    .help(core.stale ? "Working from the copy on this Mac. NodWarden keeps trying the vault server." : "")
                }
                Spacer(minLength: 0)
                IconButton(symbol: "gearshape.fill", label: "Agents") { go(.agents) }
                if core.state == .unlocked {
                    IconButton(symbol: "lock.fill", label: "Lock") { core.lock() }
                        .transition(.blurSwap())
                }
            }
            if let n = core.notice {
                // Stays until a later success resolves it, or you dismiss it (#14, #28).
                NoticeCard(notice: n, busy: core.unlocking || core.syncing,
                           retry: n.retry.map { r in { retry(r) } },
                           dismiss: { core.notice = nil })
                    .id(n.id)
                    .transition(.blurSwap(y: -6))
            }
            if core.state == .locked {
                Button { core.unlock() } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "touchid").font(.system(size: 15, weight: .semibold))
                            .symbolEffect(.pulse, isActive: core.unlocking)
                        Text(core.unlocking ? "Waiting for Touch ID…" : "Unlock with Touch ID")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(Pill(.primary, height: 36))
                .disabled(core.unlocking)
                .transition(.blurSwap(y: 6))
            }
            if !core.windows.isEmpty {
                windowsSection.transition(.blurSwap(y: -6))
            }
        }
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: core.state)
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: core.windows.map(\.id))
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: core.notice)
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: core.headerStatus.lead + (core.headerStatus.note ?? ""))
    }

    func retry(_ r: Notice.Retry) {
        switch r {
        case .unlock:
            core.notice = nil
            if core.state == .unlocked { core.lock() }
            core.unlock()
        case .refresh:
            core.refresh()
        }
    }

    /// Windows that cover the same thing for the same program name are one row, "×N".
    struct WindowGroup: Identifiable {
        let id: String
        let kind: String, title: String, sub: String
        let ids: [String]
        let until: Date
        let total: Double
    }

    var groups: [WindowGroup] {
        Dictionary(grouping: core.windows) { "\($0.kind)|\($0.title)|\($0.sub)" }
            .compactMap { k, ws in
                guard let last = ws.max(by: { $0.until < $1.until }) else { return nil }
                return WindowGroup(id: k, kind: last.kind, title: last.title, sub: last.sub,
                                   ids: ws.map(\.id), until: last.until, total: last.total)
            }
            .sorted { $0.until > $1.until }
    }

    var windowsSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionLabel(text: "Allowed without asking") {
                // Open windows are visible and can be ended, so one you didn't mean to open is
                // caught (#5).
                Button("End all") { core.endWindows() }
                    .buttonStyle(.plain)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.75))
            }
            Card {
                ForEach(Array(groups.enumerated()), id: \.element.id) { i, g in
                    if i > 0 { RowDivider() }
                    Row(symbol: symbol(g.kind), title: g.title, sub: g.sub, count: g.ids.count, hidden: g.kind == "login" || g.kind == "secret") {
                        HStack(spacing: 8) {
                            TimeRing(until: g.until, total: g.total)
                            XButton(label: "End \(g.title)") { core.endWindows(g.ids) }
                        }
                    }
                    .transition(.blurSwap())
                }
            }
        }
    }

    func symbol(_ kind: String) -> String {
        switch kind {
        case "login": return "terminal.fill"
        case "git": return "signature"
        case "secret": return "key.fill"
        default: return "questionmark"
        }
    }

    // MARK: agents (GitHub #3)

    func subHeader(_ title: String, _ sub: String, back: Page, trailing: AnyView? = nil) -> some View {
        HStack(spacing: 12) {
            IconButton(symbol: "chevron.left", label: "Back") { go(back) }
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 15, weight: .semibold))
                Text(sub).font(.system(size: 12)).foregroundStyle(.white.opacity(0.5)).lineLimit(1)
            }
            Spacer(minLength: 0)
            if let trailing { trailing }
        }
    }

    var agents: some View {
        VStack(alignment: .leading, spacing: 14) {
            tabsHeader
            if core.paired.isEmpty && core.tokens.isEmpty {
                HStack {
                    Text("No agents yet. Make a token and give it to one.")
                        .font(.system(size: 12)).foregroundStyle(.white.opacity(0.5))
                    Spacer()
                    newTokenLink
                }
                .padding(.horizontal, 4)
            }
            if !core.paired.isEmpty {
                VStack(alignment: .leading, spacing: 7) {
                    SectionLabel(text: "Paired") { EmptyView() }
                    Card {
                        ForEach(Array(core.paired.enumerated()), id: \.element.id) { i, a in
                            if i > 0 { RowDivider() }
                            Row(symbol: "desktopcomputer", title: a.label,
                                sub: "Paired \(day(a.since)) · \(seen(a.seen))") {
                                HStack(spacing: 6) {
                                    EditButton(label: "Rename \(a.label)") { name = a.name ?? ""; go(.rename(a, device: true)) }
                                    XButton(label: "Remove \(a.label)") { go(.confirm(.device(a))) }
                                }
                            }
                        }
                    }
                }
            }
            if !core.tokens.isEmpty {
                VStack(alignment: .leading, spacing: 7) {
                    SectionLabel(text: "Tokens") { newTokenLink }
                    Card {
                        ForEach(Array(core.tokens.enumerated()), id: \.element.id) { i, t in
                            if i > 0 { RowDivider() }
                            Row(symbol: "key.horizontal.fill", title: t.label, sub: tokenUse(t)) {
                                HStack(spacing: 6) {
                                    EditButton(label: "Rename \(t.label)") { name = t.name ?? ""; go(.rename(t, device: false)) }
                                    XButton(label: "Delete \(t.label)") { go(.confirm(.token(t))) }
                                }
                            }
                        }
                    }
                }
            }
            if !core.paired.isEmpty || !core.tokens.isEmpty {
                DangerLink(title: "Revoke everything", help: "Remove every agent and token") { go(.confirm(.all)) }
            }
        }
        .onAppear { core.loadAgents() }
    }

    /// Use is recorded from this version on; older use is unknown, not "never".
    func tokenUse(_ t: Agent) -> String {
        guard let last = t.seen else { return "Created \(day(t.since)) · no use recorded" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        let when = Date().timeIntervalSince(last) < 120 ? "just now" : f.localizedString(for: last, relativeTo: Date())
        return "Last used \(when)" + (t.usedBy.map { " · by \($0)" } ?? "")
    }

    var newTokenLink: some View {
        Button { name = ""; go(.newToken) } label: {
            Label("New token", systemImage: "plus").labelStyle(.titleAndIcon)
        }
        .buttonStyle(.plain)
        .font(.system(size: 11.5, weight: .semibold))
        .foregroundStyle(.white.opacity(0.8))
    }

    /// ‹ back on the left, the Agents | History switch on the right.
    var tabsHeader: some View {
        HStack(spacing: 10) {
            IconButton(symbol: "chevron.left", label: "Back") { go(.home) }
            Spacer(minLength: 0)
            Segmented(options: ["Agents", "History"], selected: page == .history ? 1 : 0) { i in
                go(i == 0 ? .agents : .history)
            }
            .frame(width: 200)
        }
    }

    // MARK: history

    @State private var showAll = false

    var historyPage: some View {
        VStack(alignment: .leading, spacing: 14) {
            tabsHeader
            if core.history.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "clock.arrow.circlepath").font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.35))
                    Text("Nothing yet").font(.system(size: 13, weight: .semibold)).foregroundStyle(.white.opacity(0.7))
                    Text("Requests you allow or deny show up here.\nKept in memory; cleared when NodWarden quits.")
                        .font(.system(size: 11)).foregroundStyle(.white.opacity(0.45)).multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 18)
            } else {
                let shown = Array(core.history.prefix(showAll ? 25 : 5))
                Group {
                    if showAll {
                        ScrollView(.vertical, showsIndicators: false) { historyDays(shown) }
                            .frame(height: 300)
                            .mask(LinearGradient(stops: [.init(color: .black, location: 0.88), .init(color: .clear, location: 1)],
                                                 startPoint: .top, endPoint: .bottom))
                    } else {
                        historyDays(shown)
                    }
                }
                if core.history.count > 5 {
                    Button(showAll ? "Show less" : "Show more") {
                        withAnimation(reduceMotion ? .easeOut(duration: 0.15) : springOpen) { showAll.toggle() }
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.75))
                    .padding(.horizontal, 4)
                }
                DangerLink(title: "Clear history", help: "Forget every entry now") {
                    withAnimation(reduceMotion ? .easeOut(duration: 0.15) : springSwap) {
                        core.history.removeAll()
                        showAll = false
                    }
                }
            }
        }
    }

    func historyDays(_ entries: [HistoryEntry]) -> some View {
        let days = Dictionary(grouping: entries) { Calendar.current.startOfDay(for: $0.at) }
            .sorted { $0.key > $1.key }
        return VStack(alignment: .leading, spacing: 10) {
            ForEach(days, id: \.key) { day, items in
                VStack(alignment: .leading, spacing: 7) {
                    SectionLabel(text: dayLabel(day)) { EmptyView() }
                    Card {
                        ForEach(Array(items.enumerated()), id: \.element.id) { i, h in
                            if i > 0 { RowDivider() }
                            Row(symbol: symbol(h.kind), title: h.title, sub: h.sub,
                                hidden: h.kind == "login" || h.kind == "secret", hiddenSub: h.kind == "secret") {
                                VStack(alignment: .trailing, spacing: 3) {
                                    ResultBadge(result: h.result, count: h.count)
                                    Text(h.at, format: .dateTime.hour().minute())
                                        .font(.system(size: 10.5).monospacedDigit()).foregroundStyle(.white.opacity(0.4))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    func dayLabel(_ d: Date) -> String {
        if Calendar.current.isDateInToday(d) { return "Today" }
        if Calendar.current.isDateInYesterday(d) { return "Yesterday" }
        return d.formatted(.dateTime.day().month(.abbreviated))
    }

    func day(_ d: Date) -> String { d.formatted(.dateTime.month(.abbreviated).day()) }

    func seen(_ d: Date?) -> String {
        guard let d else { return "never connected" }
        if Date().timeIntervalSince(d) < 120 { return "active now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return "last seen \(f.localizedString(for: d, relativeTo: Date()))"
    }

    func confirmText(_ r: Removal) -> (symbol: String, title: String, detail: String, reason: String) {
        switch r {
        case .device(let a):
            return ("desktopcomputer", "Remove “\(a.label)”?",
                    a.name == nil
                        ? "Forgets this device now. It has no name, so its token can't be found; revoke everything to be sure."
                        : "It loses access now and needs a new token to come back.",
                    "remove the agent \(a.label)")
        case .token(let t):
            return ("key.horizontal.fill", "Delete token “\(t.label)”?",
                    "No new device can pair with it. Devices already paired stay.",
                    "delete the agent token \(t.label)")
        case .all:
            return ("exclamationmark.triangle.fill", "Revoke everything?",
                    "Every agent loses access and needs a new token to come back.",
                    "remove every agent and token")
        }
    }

    func confirm(_ r: Removal) -> some View {
        let t = confirmText(r)
        return VStack(alignment: .leading, spacing: 14) {
            subHeader("Agents", "Who can ask for secrets", back: .agents)
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .top, spacing: 10) {
                        Tile(symbol: t.symbol)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(t.title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                            Text(t.detail).font(.system(size: 11)).foregroundStyle(.white.opacity(0.55))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    if let problem {
                        Text(problem).font(.system(size: 11)).foregroundStyle(.orange.opacity(0.9))
                    }
                    HStack(spacing: 8) {
                        Spacer()
                        Button("Cancel") { go(.agents) }.buttonStyle(Pill(.quiet))
                            .keyboardShortcut(.cancelAction)
                        Button { remove(r, reason: t.reason) } label: {
                            HStack(spacing: 6) {
                                Image(systemName: "touchid").symbolEffect(.pulse, isActive: removing)
                                Text(r == .all ? "Revoke" : "Remove")
                            }
                        }
                        .buttonStyle(Pill(.danger))
                        .disabled(removing)
                    }
                }
                .padding(12)
            }
        }
        // Touch ID starts by itself, like a request; Remove asks again after a cancel.
        .onAppear { remove(r, reason: t.reason) }
        .onDisappear { prompt?.invalidate(); prompt = nil; removing = false }
    }

    /// Removing access needs Touch ID, like releasing it.
    func remove(_ r: Removal, reason: String) {
        guard !removing else { return }
        removing = true
        problem = nil
        let ctx = LAContext()
        prompt = ctx
        confirmPresence(ctx, reason) { ok, why in
            // A prompt cancelled by leaving the card answers late; ignore it.
            guard prompt === ctx else { return }
            prompt = nil
            removing = false
            guard ok else {
                problem = why ?? "Touch ID was cancelled. Click Remove to try again."
                return
            }
            switch r {
            case .device(let a): core.removeDevice(a.id)
            case .token(let t): core.removeToken(t.id)
            case .all: core.revokeAll()
            }
            go(.agents)
        }
    }

    // MARK: rename

    /// Same field as a new token. Renaming takes no Touch ID, like naming one. A device's
    /// token gets the new name too, so it stays the same after the next pairing.
    func rename(_ a: Agent, device: Bool) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            subHeader(device ? "Rename device" : "Rename token", "Now: \(a.label)", back: .agents)
            nameField(button: "Save") {
                core.rename(a, device: device, to: name.trimmingCharacters(in: .whitespaces))
                go(.agents)
            }
        }
    }

    func nameField(button: String, busy: Bool = false, action: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            TextField("e.g. laptop-claude", text: $name)
                .textFieldStyle(.plain)
                .font(.system(size: 13))
                .focused($nameFocused)
                .onSubmit(action)
                .padding(.horizontal, 12)
                .frame(height: 36)
                .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(.white.opacity(nameFocused ? 0.3 : 0.12), lineWidth: 1))
            Button(button, action: action)
                .buttonStyle(Pill(.primary, height: 36))
                .disabled(busy)
        }
        .onAppear {
            islandPanel()?.makeKey()
            DispatchQueue.main.async { nameFocused = true }
        }
        .onDisappear { releaseKeyboard() }
    }

    // MARK: new token

    var newToken: some View {
        VStack(alignment: .leading, spacing: 14) {
            subHeader("New agent token", "Give it a name you'll recognise in requests", back: .agents)
            nameField(button: creating ? "Creating…" : "Create", busy: creating, action: create)
            if core.relayNote != nil {
                Label("Waiting for the Agent Access relay", systemImage: "antenna.radiowaves.left.and.right.slash")
                    .font(.system(size: 11)).foregroundStyle(.white.opacity(0.5))
            }
        }
    }

    func create() {
        guard !creating else { return }
        let n = name.trimmingCharacters(in: .whitespaces)
        createdName = n.isEmpty ? nil : n
        creating = true
        core.newToken(name: n)
    }

    // MARK: token created

    var tokenCreated: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(.green.opacity(0.18))
                    Image(systemName: "checkmark").font(.system(size: 14, weight: .bold)).foregroundStyle(.green)
                }
                .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 1) {
                    Text(createdName.map { "\($0) is ready" } ?? "Agent token ready")
                        .font(.system(size: 15, weight: .semibold)).lineLimit(1)
                    Text("Copy the token once. It won't be shown again.")
                        .font(.system(size: 12)).foregroundStyle(.white.opacity(0.5))
                }
                Spacer(minLength: 0)
            }
            HStack(spacing: 8) {
                Text(String(repeating: "•", count: 28))
                    .font(.system(size: 12.5, design: .monospaced)).foregroundStyle(.white.opacity(0.75))
                    .padding(.horizontal, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .frame(height: 36)
                    .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .accessibilityLabel("Token, hidden")
                Button(action: copyToken) {
                    HStack(spacing: 6) { Image(systemName: "doc.on.doc"); Text("Copy") }
                }
                .buttonStyle(Pill(.primary, height: 36))
            }
            Text("On the agent's machine:  AAC_TOKEN=… aac run --domain …")
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.white.opacity(0.45))
        }
    }

    func copyToken() {
        guard let token = core.token else { return }
        // Current host only (no Universal Clipboard), and marked concealed so clipboard
        // managers don't keep it (#6).
        let pb = NSPasteboard.general
        pb.prepareForNewContents(with: .currentHostOnly)
        pb.declareTypes([.string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")], owner: nil)
        pb.setString(token, forType: .string)
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        core.token = nil
        createdName = nil
        go(.agents)
    }
}

// MARK: - Building blocks

/// State colours, deeper than the bright brand amber so a dot never reads as part of the logo.
enum Tint {
    static let brand = Color(red: 0.92, green: 0.62, blue: 0.05)
    static let ok = Color(red: 0.16, green: 0.62, blue: 0.33)
    static let warn = Color(red: 0.89, green: 0.40, blue: 0.10)
    static let bad = Color(red: 0.85, green: 0.20, blue: 0.20)
}

/// "Nod" in the brand amber, "Warden" in white, as in the logo.
struct Wordmark: View {
    var size: CGFloat = 15
    var body: some View {
        (Text("Nod").foregroundColor(Tint.brand) + Text("Warden"))
            .font(.system(size: size, weight: .heavy))
            .tracking(-0.2)
            .accessibilityLabel("NodWarden")
    }
}

/// Two-option switch; the selected one is a white pill.
struct Segmented: View {
    let options: [String]
    let selected: Int
    let pick: (Int) -> Void
    @Namespace private var ns
    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(options.enumerated()), id: \.offset) { i, t in
                Button { pick(i) } label: {
                    Text(t).font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(i == selected ? .black : .white.opacity(0.7))
                        .frame(maxWidth: .infinity).frame(height: 26)
                        .background {
                            if i == selected { Capsule().fill(.white).matchedGeometryEffect(id: "tab", in: ns) }
                        }
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(i == selected ? .isSelected : [])
            }
        }
        .padding(3)
        .background(.white.opacity(0.1), in: Capsule())
        .animation(springSwap, value: selected)
    }
}

/// The one destructive action at the end of a tab: centred red text (Revoke everything,
/// Clear history).
struct DangerLink: View {
    let title: String
    let help: String
    let action: () -> Void
    var body: some View {
        Button(title, action: action)
            .buttonStyle(.plain)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(Pill.dangerText)
            .frame(maxWidth: .infinity)
            .help(help)
    }
}

struct ResultBadge: View {
    let result: HistoryEntry.Result
    var count = 1
    var style: (String, Color) {
        switch result {
        case .allowed: return ("Allowed", Tint.ok)
        case .auto: return (count > 1 ? "Auto ×\(count)" : "Auto", Tint.ok)
        case .denied: return ("Denied", Tint.bad)
        case .expired: return ("Timed out", Tint.warn)
        case .cancelled: return ("Cancelled", .white.opacity(0.5))
        case .notFound: return ("No match", .white.opacity(0.5))
        case .locked: return (count > 1 ? "Locked ×\(count)" : "Locked", .white.opacity(0.5))
        }
    }
    var body: some View {
        let (t, c) = style
        Text(t).font(.system(size: 10.5, weight: .bold)).foregroundStyle(c)
            .padding(.horizontal, 8).frame(height: 20)
            .background(c.opacity(0.14), in: Capsule())
    }
}

/// Drifting, twinkling specks; positions come from a fixed seed so they don't jump on redraw.
struct Ink: View {
    @Environment(\.accessibilityReduceMotion) private var still
    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30, paused: still)) { ctx in
            let t = still ? 0 : ctx.date.timeIntervalSinceReferenceDate
            Canvas { g, size in
                let n = Int(size.width * size.height / 4)
                var seed: UInt64 = 0x9E3779B97F4A7C15
                func rnd() -> Double {
                    seed &+= 0x9E3779B97F4A7C15
                    var z = seed
                    z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
                    z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
                    return Double(z ^ (z >> 31)) / Double(UInt64.max)
                }
                for _ in 0..<n {
                    let x0 = rnd() * size.width, y0 = rnd() * size.height
                    let speed = 1.5 + rnd() * 3.5, angle = rnd() * .pi * 2, phase = rnd() * 6
                    let x = (x0 + cos(angle) * speed * t).truncatingRemainder(dividingBy: size.width)
                    let y = (y0 + sin(angle) * speed * t).truncatingRemainder(dividingBy: size.height)
                    let a = 0.3 + 0.5 * (0.5 + 0.5 * sin(t * 2 + phase))
                    let r = 0.25 + rnd() * 0.25
                    g.fill(Path(ellipseIn: CGRect(x: (x + size.width).truncatingRemainder(dividingBy: size.width) - r,
                                                  y: (y + size.height).truncatingRemainder(dividingBy: size.height) - r,
                                                  width: r * 2, height: r * 2)),
                           with: .color(.white.opacity(a)))
                }
            }
        }
    }
}


/// A state dot; it breathes while something is waiting on you.
struct StateDot: View {
    let color: Color
    var pulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        if pulse && !reduceMotion {
            Circle().fill(color).frame(width: 7, height: 7)
                .phaseAnimator([1.0, 0.3]) { c, o in c.opacity(o) } animation: { _ in .easeInOut(duration: 0.8) }
        } else {
            Circle().fill(color).frame(width: 7, height: 7)
        }
    }
}

/// A problem, worded for people: tinted icon, title, one line of what it means, and Retry when
/// trying again can help.
struct NoticeCard: View {
    let notice: Notice
    var busy = false
    var retry: (() -> Void)?
    var dismiss: () -> Void

    var tint: Color {
        switch notice.tone {
        case .info: return .white.opacity(0.75)
        case .warning: return Tint.warn
        case .error: return Tint.bad
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous).fill(tint.opacity(0.16))
                Image(systemName: notice.symbol).font(.system(size: 13, weight: .semibold)).foregroundStyle(tint)
            }
            .frame(width: 30, height: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(notice.title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(notice.detail).font(.system(size: 11)).foregroundStyle(.white.opacity(0.55))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 6)
            if let retry {
                Button(action: retry) {
                    if busy {
                        ProgressView().controlSize(.mini).tint(.white).frame(width: 34)
                    } else {
                        Text("Retry")
                    }
                }
                .buttonStyle(Pill(.quiet, height: 26))
                .disabled(busy)
            } else {
                XButton(label: "Dismiss", action: dismiss)
            }
        }
        .padding(10)
        .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(tint.opacity(0.18), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

struct IconButton: View {
    let symbol: String
    let label: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .semibold))
                .frame(width: 30, height: 30)
                .background(.white.opacity(hover ? 0.18 : 0.1), in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hover = h } }
        .help(label)
        .accessibilityLabel(label)
    }
}

/// Small "sync now" arrow; turns while a sync runs.
struct SyncButton: View {
    let spinning: Bool
    let action: () -> Void
    @State private var hover = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        Button(action: action) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(Tint.warn.opacity(hover ? 1 : 0.8))
                .rotationEffect(.degrees(spinning && !reduceMotion ? 360 : 0))
                .animation(spinning && !reduceMotion ? .linear(duration: 1).repeatForever(autoreverses: false) : .default,
                           value: spinning)
                .frame(width: 18, height: 18)
                .background(Tint.warn.opacity(hover ? 0.2 : 0.1), in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(spinning)
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hover = h } }
        .help("Sync now")
        .accessibilityLabel("Sync now")
    }
}

struct EditButton: View {
    let label: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: "pencil").font(.system(size: 10, weight: .bold))
                .foregroundStyle(.white.opacity(hover ? 0.95 : 0.6))
                .frame(width: 22, height: 22)
                .background(.white.opacity(hover ? 0.16 : 0.08), in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hover = h } }
        .help(label)
        .accessibilityLabel(label)
    }
}

struct XButton: View {
    let label: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: "xmark").font(.system(size: 10, weight: .bold))
                .foregroundStyle(.white.opacity(hover ? 0.95 : 0.6))
                .frame(width: 22, height: 22)
                .background(.white.opacity(hover ? 0.16 : 0.08), in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hover = h } }
        .help(label)
        .accessibilityLabel(label)
    }
}

struct Tile: View {
    let symbol: String
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8, style: .continuous).fill(.white.opacity(0.1))
            Image(systemName: symbol).font(.system(size: 13, weight: .semibold))
        }
        .frame(width: 30, height: 30)
    }
}

struct SectionLabel<Action: View>: View {
    let text: String
    @ViewBuilder var action: Action
    var body: some View {
        HStack {
            Text(text.uppercased()).font(.system(size: 10.5, weight: .semibold)).tracking(0.6)
                .foregroundStyle(.white.opacity(0.4))
            Spacer()
            action
        }
        .padding(.horizontal, 4)
    }
}

struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) { content }
            .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

struct RowDivider: View {
    var body: some View { Rectangle().fill(.white.opacity(0.07)).frame(height: 1).padding(.leading, 50) }
}

struct Row<Trailing: View>: View {
    let symbol: String
    let title: String
    let sub: String
    var count = 1
    /// Mask the title (a host, item name or login) until clicked; its first letters stay.
    var hidden = false
    /// Mask the sub line's first part too (a username), keeping what follows " · ".
    var hiddenSub = false
    @ViewBuilder var trailing: Trailing
    @State private var revealed = false
    var body: some View {
        HStack(spacing: 10) {
            Tile(symbol: symbol)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    MaskedText(text: title, masked: hidden && !revealed)
                        .font(.system(size: 13, weight: .semibold))
                    if count > 1 {
                        Text("×\(count)").font(.system(size: 10, weight: .bold))
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.white.opacity(0.14), in: Capsule())
                    }
                }
                subLine.font(.system(size: 11)).foregroundStyle(.white.opacity(0.5))
            }
            .contentShape(Rectangle())
            .onTapGesture {
                guard hidden || hiddenSub else { return }
                withAnimation(.easeOut(duration: 0.3)) { revealed.toggle() }
            }
            .help(hidden || hiddenSub ? (revealed ? "Click to hide" : "Click to show") : "")
            Spacer(minLength: 8)
            trailing
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .onDisappear { revealed = false }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder var subLine: some View {
        if hiddenSub, let r = sub.range(of: " · ") {
            HStack(spacing: 0) {
                MaskedText(text: String(sub[..<r.lowerBound]), masked: !revealed)
                Text(sub[r.lowerBound...]).lineLimit(1)
            }
        } else {
            Text(sub).lineLimit(1)
        }
    }
}

/// Text with everything but a short hint drawn as "invisible ink": the first two letters and
/// the punctuation (@ . : - · space) stay, so you can tell rows apart; letters and digits after
/// that are not drawn at all, only drifting specks where they would be. So a screenshot or a
/// screen recording of the notch shows "ro••@20•.•.•.•" and never the host itself.
struct MaskedText: View {
    let text: String
    let masked: Bool
    static let keep = 2

    /// Runs of (text, hidden).
    var runs: [(String, Bool)] {
        var out: [(String, Bool)] = []
        for (i, c) in text.enumerated() {
            let hide = i >= MaskedText.keep && (c.isLetter || c.isNumber)
            if let last = out.last, last.1 == hide { out[out.count - 1].0.append(c) } else { out.append((String(c), hide)) }
        }
        return out
    }

    var body: some View {
        if !masked {
            Text(text).lineLimit(1).truncationMode(.middle).transition(.opacity)
        } else {
            HStack(spacing: 0) {
                ForEach(Array(runs.enumerated()), id: \.offset) { _, r in
                    if r.1 {
                        // Same width as the real letters, so the row keeps its shape; nothing of
                        // them is drawn.
                        Text(r.0).hidden().overlay { Ink() }
                    } else {
                        Text(r.0)
                    }
                }
            }
            .lineLimit(1)
            .fixedSize()
            .accessibilityLabel("\(text.prefix(MaskedText.keep)), hidden. Click the row to show.")
            .transition(.opacity)
        }
    }
}

/// Time left in an Allow window: the ring drains, minutes (then seconds) in the middle.
struct TimeRing: View {
    let until: Date
    let total: Double
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let left = max(0, until.timeIntervalSince(ctx.date))
            ZStack {
                Circle().stroke(.white.opacity(0.12), lineWidth: 2.5)
                Circle().trim(from: 0, to: left / total)
                    .stroke(Color.green.opacity(0.85), style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .animation(.linear(duration: 1), value: left)
                Text(left >= 60 ? "\(Int((left / 60).rounded(.up)))m" : "\(Int(left))s")
                    .font(.system(size: 9.5, weight: .bold).monospacedDigit())
                    .foregroundStyle(.white.opacity(0.85))
            }
            .frame(width: 30, height: 30)
            .accessibilityLabel("\(Int((left / 60).rounded(.up))) minutes left")
        }
    }
}
