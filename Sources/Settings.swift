import AppKit
import ServiceManagement
import SwiftUI

/// Your choices, kept as app preferences (io.github.nodwarden). Any program running as you can
/// change those, so no setting can skip Touch ID: at most it hides things or asks more often.
final class Settings: ObservableObject {
    static let shared = Settings()
    private let d = UserDefaults.standard

    private func bool(_ key: String, _ fallback: Bool) -> Bool { d.object(forKey: key) as? Bool ?? fallback }

    /// Mask hosts, items and usernames in History and the Allow list.
    @Published var maskLists: Bool { didSet { d.set(maskLists, forKey: "maskLists") } }
    /// Mask them on the request card and in the Touch ID prompt too.
    @Published var maskRequests: Bool { didSet { d.set(maskRequests, forKey: "maskRequests") } }
    @Published var keepHistory: Bool { didSet { d.set(keepHistory, forKey: "keepHistory") } }
    /// Minutes without keyboard or mouse before locking; 0 = never.
    @Published var idleLockMinutes: Int { didSet { d.set(idleLockMinutes, forKey: "idleLockMinutes") } }
    @Published var lockOnSleep: Bool { didSet { d.set(lockOnSleep, forKey: "lockOnSleep") } }
    @Published var offerWindows: Bool { didSet { d.set(offerWindows, forKey: "offerWindows") } }
    @Published var autoTouchID: Bool { didSet { d.set(autoTouchID, forKey: "autoTouchID") } }
    @Published var sound: Bool { didSet { d.set(sound, forKey: "sound") } }
    /// Work from the copy on this Mac when the vault server can't be reached. The core enforces it.
    @Published var offlineCopy: Bool { didSet { d.set(offlineCopy, forKey: "offlineCopy") } }

    static let idleChoices = [0, 5, 15, 30, 60]

    private init() {
        maskLists = d.object(forKey: "maskLists") as? Bool ?? true
        maskRequests = d.object(forKey: "maskRequests") as? Bool ?? false
        keepHistory = d.object(forKey: "keepHistory") as? Bool ?? true
        idleLockMinutes = d.object(forKey: "idleLockMinutes") as? Int ?? 15
        lockOnSleep = d.object(forKey: "lockOnSleep") as? Bool ?? true
        offerWindows = d.object(forKey: "offerWindows") as? Bool ?? true
        autoTouchID = d.object(forKey: "autoTouchID") as? Bool ?? true
        sound = d.object(forKey: "sound") as? Bool ?? true
        offlineCopy = d.object(forKey: "offlineCopy") as? Bool ?? true
    }
}

/// Open at login, through macOS Login Items. The switch shows what macOS reports, never just
/// what was clicked.
enum LoginItem {
    enum State: Equatable { case on, off, needsApproval, unavailable(String) }

    static var state: State {
        switch SMAppService.mainApp.status {
        case .enabled: return .on
        case .requiresApproval: return .needsApproval
        case .notFound: return .unavailable("macOS can't find NodWarden. Keep it in Applications and reopen it.")
        default: return .off
        }
    }

    /// Asks macOS; returns what it says afterwards, or why it refused.
    static func set(_ on: Bool) -> (State, String?) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            return (state, nil)
        } catch {
            return (state, (error as NSError).localizedDescription)
        }
    }

    static func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

// MARK: - Settings tab

struct SettingsPage: View {
    @ObservedObject var core: Core
    /// Snapshots render in one pass, which leaves a ScrollView empty; they draw the list flat.
    var scrolls = true
    @ObservedObject var s = Settings.shared
    /// The ⓘ whose explanation is showing.
    @State private var info: String?
    @State private var login = LoginItem.state
    @State private var loginBusy = false
    @State private var loginProblem: String?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        // Taller than the space under the notch with every section open: it scrolls.
        VStack(alignment: .leading, spacing: 12) {
            if scrolls {
                // Room at the end, so the last card scrolls clear of the fade.
                ScrollView(.vertical, showsIndicators: false) { list.padding(.bottom, 18) }
                    .frame(maxHeight: 340)
                    .mask(LinearGradient(stops: [.init(color: .black, location: 0.9), .init(color: .clear, location: 1)],
                                         startPoint: .top, endPoint: .bottom))
            } else {
                list
            }
            footer
        }
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: info)
        .onAppear { login = LoginItem.state }
        // Approving in System Settings happens outside the app; read it again on return.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            login = LoginItem.state
        }
    }

    /// Pinned under the list, never faded.
    var footer: some View {
        HStack {
            Text("NodWarden \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")")
                .foregroundStyle(.white.opacity(0.4))
            Spacer()
            Button("Open logs") {
                NSWorkspace.shared.open(FileManager.default.homeDirectoryForCurrentUser
                    .appendingPathComponent("Library/Logs/NodWarden/aac-core.log"))
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white.opacity(0.75))
        }
        .font(.system(size: 11.5, weight: .semibold))
        .padding(.horizontal, 4)
    }

    var list: some View {
            VStack(alignment: .leading, spacing: 14) {
                section("Privacy") {
                    toggle("Hide hosts and names", $s.maskLists, id: "maskLists",
                           info: "History and the Allow list show only the first letters of hosts, items and usernames. Click a row to show it. Keeps them out of screenshots and recordings.")
                    RowDivider()
                    toggle("Hide them in requests too", $s.maskRequests, id: "maskRequests",
                           info: "The request card and the Touch ID prompt show only the first letters too. You approve with less on screen.")
                    RowDivider()
                    toggle("Keep history", $s.keepHistory, id: "keepHistory",
                           info: "Lists what was asked and what happened. Kept in memory only and cleared when NodWarden quits. Off: nothing is recorded, and the list is cleared now.")
                }
                section("Lock") {
                    SettingRow(title: "Lock when idle", info: info == "idle" ? "Locks after this long without keyboard or mouse input. Never: only Lock, sleep or screen lock lock it." : nil,
                               toggleInfo: { flip("idle") }) {
                        Chips(options: Settings.idleChoices.map { $0 == 0 ? "Never" : $0 < 60 ? "\($0)m" : "1h" },
                              selected: Settings.idleChoices.firstIndex(of: s.idleLockMinutes) ?? 2) { i in
                            s.idleLockMinutes = Settings.idleChoices[i]
                        }
                    }
                    RowDivider()
                    toggle("Lock on screen lock or sleep", $s.lockOnSleep, id: "lockOnSleep",
                           info: "Also on switching users. Locking ends every Allow window.")
                }
                section("Requests") {
                    toggle("Offer “Allow for N minutes”", $s.offerWindows, id: "offerWindows",
                           info: "Off: every SSH login and git signature asks, and open windows end now.")
                    RowDivider()
                    toggle("Start Touch ID by itself", $s.autoTouchID, id: "autoTouchID",
                           info: "Off: click the fingerprint first, so a reflex touch can't approve something.")
                    RowDivider()
                    toggle("Sound", $s.sound, id: "sound", info: "The chime when a request arrives.")
                }
                section("Vault & app") {
                    toggle("Work from the offline copy", $s.offlineCopy, id: "offlineCopy",
                           info: "When the vault server can't be reached, use the copy on this Mac. Off: SSH and secrets are refused until a sync works.")
                    RowDivider()
                    loginRow
                }
            }
    }

    func flip(_ id: String) { info = info == id ? nil : id }

    func section<C: View>(_ title: String, @ViewBuilder _ c: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionLabel(text: title) { EmptyView() }
            Card { c() }
        }
    }

    func toggle(_ title: String, _ value: Binding<Bool>, id: String, info text: String) -> some View {
        SettingRow(title: title, info: info == id ? text : nil, toggleInfo: { flip(id) }) {
            Switch(isOn: value, label: title)
        }
    }

    var loginRow: some View {
        VStack(alignment: .leading, spacing: 0) {
            SettingRow(title: "Open at login",
                       info: info == "login" ? "Starts NodWarden when you log in, through macOS Login Items. Without it, SSH and git signing don't work until you open NodWarden." : nil,
                       toggleInfo: { flip("login") }) {
                ZStack {
                    Switch(isOn: Binding(get: { login == .on || login == .needsApproval }, set: setLogin),
                           label: "Open at login")
                        .opacity(loginBusy ? 0.4 : 1)
                        .disabled(loginBusy)
                    if loginBusy { ProgressView().controlSize(.mini).tint(.white) }
                }
            }
            if login == .needsApproval {
                StatusLine(color: Tint.warn, text: "Waiting for your OK in Login Items.", action: "Open") {
                    LoginItem.openSystemSettings()
                }
            } else if let why = loginProblem ?? { if case .unavailable(let w) = login { return w } else { return nil } }() {
                StatusLine(color: Tint.bad, text: why, action: "Login Items") { LoginItem.openSystemSettings() }
            }
        }
    }

    func setLogin(_ on: Bool) {
        loginBusy = true
        loginProblem = nil
        DispatchQueue.global().async {
            let (state, error) = LoginItem.set(on)
            DispatchQueue.main.async {
                login = state
                loginBusy = false
                if let error, state != (on ? .on : .off), state != .needsApproval {
                    loginProblem = "macOS refused: \(error)"
                }
            }
        }
    }
}

/// On/off switch drawn in SwiftUI, so it matches the notch and renders anywhere.
struct Switch: View {
    @Binding var isOn: Bool
    let label: String
    @Environment(\.isEnabled) private var enabled
    var body: some View {
        Button { isOn.toggle() } label: {
            Capsule()
                .fill(isOn ? Tint.ok : Color.white.opacity(0.18))
                .frame(width: 34, height: 20)
                .overlay(alignment: isOn ? .trailing : .leading) {
                    Circle().fill(.white).frame(width: 16, height: 16).padding(2)
                        .shadow(color: .black.opacity(0.25), radius: 1, y: 1)
                }
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .animation(springSwap, value: isOn)
        .accessibilityLabel(label)
        .accessibilityValue(isOn ? "On" : "Off")
        .accessibilityAddTraits(.isButton)
    }
}

/// A setting: title, ⓘ that shows its explanation below, and its control.
struct SettingRow<Control: View>: View {
    let title: String
    let info: String?
    let toggleInfo: () -> Void
    @ViewBuilder var control: Control
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Button(action: toggleInfo) {
                    Image(systemName: info == nil ? "info.circle" : "info.circle.fill")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.white.opacity(info == nil ? 0.4 : 0.8))
                        .frame(width: 18, height: 18)
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("About \(title)")
                Spacer(minLength: 8)
                control
            }
            if let info {
                Text(info).font(.system(size: 11)).foregroundStyle(.white.opacity(0.55))
                    .fixedSize(horizontal: false, vertical: true)
                    .transition(.blurSwap(y: -4))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
    }
}

/// A line under a setting saying what's wrong, with the one action that fixes it.
struct StatusLine: View {
    let color: Color
    let text: String
    let action: String
    let run: () -> Void
    var body: some View {
        HStack(spacing: 6) {
            Text(text).font(.system(size: 11)).foregroundStyle(color)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 6)
            Button(action, action: run).buttonStyle(Pill(.quiet, height: 22)).font(.system(size: 11, weight: .semibold))
        }
        .padding(.horizontal, 12)
        .padding(.bottom, 9)
        .transition(.blurSwap(y: -4))
    }
}

/// A compact choice of a few options.
struct Chips: View {
    let options: [String]
    let selected: Int
    let pick: (Int) -> Void
    @Namespace private var ns
    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(options.enumerated()), id: \.offset) { i, t in
                Button { pick(i) } label: {
                    Text(t).font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(i == selected ? .black : .white.opacity(0.7))
                        .padding(.horizontal, 8).frame(height: 22)
                        .background {
                            if i == selected { Capsule().fill(.white).matchedGeometryEffect(id: "chip", in: ns) }
                        }
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(i == selected ? .isSelected : [])
            }
        }
        .padding(2)
        .background(.white.opacity(0.1), in: Capsule())
        .animation(springSwap, value: selected)
    }
}
