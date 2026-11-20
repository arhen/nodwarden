import AppKit
import Combine
import LocalAuthentication
import SwiftUI

// MARK: - Window

final class IslandPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let core = Core()
    let layout = Layout()
    var panel: IslandPanel!
    var sigterm: DispatchSourceSignal?
    var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ n: Notification) {
        // Tall enough for the Agents page; clicks outside the island fall through anyway.
        let frameW: CGFloat = 640, frameH: CGFloat = 600
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
        // Writing to a dead aac-core pipe must not kill the app (#8).
        signal(SIGPIPE, SIG_IGN)
        // Lock when the Mac sleeps or the screen locks, so no Allow window survives you walking away (#6).
        let lockNow: (Notification) -> Void = { [weak self] _ in self?.core.lock() }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main, using: lockNow)
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main, using: lockNow)
        DistributedNotificationCenter.default().addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main, using: lockNow)
        // Fast user switching: someone else now has the screen and this session runs on behind it.
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main, using: lockNow)
        startIdleLock()
        signal(SIGTERM, SIG_IGN)
        sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigterm?.setEventHandler { NSApp.terminate(nil) }
        sigterm?.resume()
        core.start()
        core.watchNetwork()
        // Ask for Touch ID once, the first time the listener is ready and locked (not on a timer).
        core.$state
            .first { $0 == .locked }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.core.unlock() }
            .store(in: &cancellables)
    }

    /// Locks after this many minutes with no keyboard or mouse input (#26), so no vault session
    /// or Allow window outlives you walking away with the screen on. `defaults write
    /// io.github.nodwarden idleLockMinutes -int N` changes it; 0 turns it off.
    var idleLockMinutes: Double {
        let v = UserDefaults.standard.object(forKey: "idleLockMinutes") as? Double
        return v ?? 15
    }
    var idleTimer: Timer?
    func startIdleLock() {
        let t = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
            guard let self, self.idleLockMinutes > 0, self.core.state == .unlocked else { return }
            let anyInput = CGEventType(rawValue: ~0)!
            // Hardware input only: events posted by programs (jigglers, scripts) don't count (#9).
            let idle = CGEventSource.secondsSinceLastEventType(.hidSystemState, eventType: anyInput)
            if idle >= self.idleLockMinutes * 60 { self.core.lock() }
        }
        t.tolerance = 10
        RunLoop.main.add(t, forMode: .common)
        idleTimer = t
    }

    func place(w: CGFloat, h: CGFloat) {
        layout.notch = Notch.current
        guard let s = NSScreen.screens.first(where: { $0.safeAreaInsets.top > 0 }) ?? NSScreen.main else { return }
        panel.setFrame(NSRect(x: s.frame.midX - w / 2, y: s.frame.maxY - h, width: w, height: h), display: true)
    }

    /// The panel is larger than the island; let clicks outside the island fall
    /// through to whatever is underneath (the menu bar, other windows).
    /// Driven by mouse-move events instead of a 30 Hz timer, so it costs nothing when idle (#24).
    var mouseMonitors: [Any] = []
    func trackClickThrough() {
        let update: (NSEvent?) -> Void = { [weak self] _ in
            guard let self else { return }
            let f = self.panel.frame, s = self.layout.size
            let island = NSRect(x: f.midX - s.width / 2, y: f.maxY - s.height, width: s.width, height: s.height)
            let over = island.insetBy(dx: -4, dy: -4).contains(NSEvent.mouseLocation)
            if self.panel.ignoresMouseEvents == over { self.panel.ignoresMouseEvents = !over }
        }
        let kinds: NSEvent.EventTypeMask = [.mouseMoved, .leftMouseDragged]
        if let g = NSEvent.addGlobalMonitorForEvents(matching: kinds, handler: { update($0) }) { mouseMonitors.append(g) }
        if let l = NSEvent.addLocalMonitorForEvents(matching: kinds, handler: { update($0); return $0 }) { mouseMonitors.append(l) }
        // The island also resizes under a still pointer; re-check when it does.
        layout.onResize = { update(nil) }
        update(nil)
    }

    func applicationWillTerminate(_ n: Notification) { core.stop() }
}

// Renders each state to PNG with fake data: `nodwarden --snapshot <dir>`.
@MainActor
func snapshot(to dir: String) {
    let sample = CredRequest(id: 1, title: "GitHub", detail: "octocat  ·  github.com  ·  + 2FA code",
                             device: "a1b2c3d4e5f6", arrived: Date(), timeout: 110)
    func shot(_ name: String, _ hover: Bool = false, _ pinned: Bool = false, granted: Int? = nil, waiting: Bool = false, _ setup: (Core) -> Void) {
        let core = Core()
        setup(core)
        let v = IslandView(core: core, layout: Layout(), hoveringInitial: hover, pinnedInitial: pinned, grantedInitial: granted, confirmingInitial: waiting)
            .frame(width: 640, height: 300)
            .background(LinearGradient(colors: [Color(red: 0.16, green: 0.20, blue: 0.32), Color(red: 0.08, green: 0.09, blue: 0.14)],
                                       startPoint: .top, endPoint: .bottom))
        let r = ImageRenderer(content: v)
        r.scale = 2
        guard let img = r.nsImage, let tiff = img.tiffRepresentation,
              let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]) else { return }
        try? png.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
    }
    // The status pages size themselves after layout, which a one-pass render doesn't do: draw
    // them in the island shape directly.
    func page(_ name: String, _ p: Page, _ setup: (Core) -> Void) {
        let core = Core()
        setup(core)
        let v = PanelView(core: core, page: .constant(p))
            .foregroundStyle(.white)
            .padding(.horizontal, 26).padding(.top, 46).padding(.bottom, 22)
            .frame(width: 460)
            .background(IslandShape(top: 8, bottom: 30).fill(.black))
            .environment(\.colorScheme, .dark)
            .padding(.horizontal, 90).padding(.bottom, 40)
            .frame(width: 640, alignment: .top)
            .background(LinearGradient(colors: [Color(red: 0.16, green: 0.20, blue: 0.32), Color(red: 0.08, green: 0.09, blue: 0.14)],
                                       startPoint: .top, endPoint: .bottom))
        let r = ImageRenderer(content: v)
        r.scale = 2
        guard let img = r.nsImage, let tiff = img.tiffRepresentation,
              let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]) else { return }
        try? png.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
    }
    let now = Date()
    let agents: (Core) -> Void = {
        $0.state = .unlocked
        $0.paired = [Agent(id: "7f3a9c0011", name: "claude-code", since: now.addingTimeInterval(-86400), seen: now),
                     Agent(id: "9b21de4400", name: nil, since: now.addingTimeInterval(-90000), seen: now.addingTimeInterval(-32400))]
        $0.tokens = [Agent(id: "825a9a1100", name: nil, since: now.addingTimeInterval(-90000), seen: now.addingTimeInterval(-300), usedBy: "claude-code"),
                     Agent(id: "a1", name: "test-device", since: now),
                     Agent(id: "6394ec75fc", name: nil, since: now.addingTimeInterval(-86400))]
    }
    page("p1-home", .home) { $0.state = .unlocked; $0.keyCount = 14 }
    page("p2-home-windows", .home) {
        $0.state = .unlocked
        $0.keyCount = 14
        $0.windows = [AllowWindow(id: "a", kind: "git", title: "Git signing", sub: "Signin Key · zsh", until: now.addingTimeInterval(1500), total: 3600),
                      AllowWindow(id: "b", kind: "git", title: "Git signing", sub: "Signin Key · zsh", until: now.addingTimeInterval(900), total: 3600),
                      AllowWindow(id: "c", kind: "login", title: "git@github.com", sub: "Github Key · zsh", until: now.addingTimeInterval(1200), total: 3600),
                      AllowWindow(id: "d", kind: "login", title: "root@203.0.113.7", sub: "Server Key · fish", until: now.addingTimeInterval(240), total: 600)]
    }
    page("p3-home-locked", .home) { $0.state = .locked }
    page("p3b-locked-desktop", .home) { $0.state = .locked; $0.show("desktop_unreachable") }
    page("p8-offline-stale", .home) { $0.state = .unlocked; $0.keyCount = 14; $0.stale = true }
    page("p8a-offline-syncing", .home) { $0.state = .unlocked; $0.keyCount = 14; $0.stale = true; $0.syncing = true }
    page("p8b-no-keys", .home) { $0.state = .unlocked; $0.keyCount = 0; $0.stale = true; $0.show("keys_offline") }
    page("p9-relay-paused", .home) { $0.state = .unlocked; $0.keyCount = 14; $0.relayNote = "relay disconnected" }
    page("p9b-starting", .home) { $0.state = .starting }
    page("p9c-stopped", .home) { $0.state = .offline("listener exited (1)") }
    page("p9d-unlocking", .home) { $0.state = .locked; $0.unlocking = true }
    page("p8c-login", .home) { $0.state = .unlocked; $0.keyCount = 14; $0.stale = true; $0.show("login") }
    page("p4-agents", .agents, agents)
    page("p4b-agents-empty", .agents) { $0.state = .unlocked }
    page("p5-confirm-device", .confirm(.device(Agent(id: "9b21de4400", name: nil, since: now))), agents)
    page("p5b-confirm-all", .confirm(.all), agents)
    page("p6-new-token", .newToken) { $0.state = .unlocked }
    page("p6b-rename", .rename(Agent(id: "825a9a1100", name: nil, since: now), device: false)) { $0.state = .unlocked }
    page("p7-token-created", .home) { $0.state = .unlocked; $0.token = "not-a-real-token" }

    shot("1-idle") { $0.state = .unlocked }
    shot("1b-idle-locked") { $0.state = .locked }
    shot("2-hover", true) { $0.state = .unlocked }
    shot("3-request", waiting: true) { $0.state = .unlocked; $0.queue = [sample] }
    shot("3a-cancelled") { $0.state = .unlocked; $0.queue = [sample] }
    shot("3c-ssh", waiting: true) {
        $0.state = .unlocked
        $0.queue = [CredRequest(id: 2, title: "git@github.com", detail: "Personal Github Key  ·  login  ·  ssh",
                                device: "ssh", arrived: Date(), timeout: 110,
                                ssh: SSHInfo(key: "Personal Github Key", purpose: "login", app: "ssh"))]
    }
    shot("3d-ssh-forwarded", waiting: true) {
        $0.state = .unlocked
        $0.queue = [CredRequest(id: 3, title: "git@github.com",
                                detail: "forwarded from build.example.com  ·  Personal Github Key  ·  login  ·  ssh",
                                device: "ssh", arrived: Date(), timeout: 110,
                                ssh: SSHInfo(key: "Personal Github Key", purpose: "login", app: "ssh",
                                             via: "build.example.com", canRemember: false))]
    }
    shot("3b-touched", granted: 1, waiting: true) { $0.state = .unlocked; $0.queue = [sample] }
    shot("4-queue") { $0.state = .unlocked; $0.queue = [sample, sample] }
    shot("5-approved") { $0.state = .unlocked; $0.outcome = .approved("github.com") }
    shot("6-denied") { $0.state = .unlocked; $0.outcome = .denied("github.com") }
    shot("6b-notfound") { $0.state = .unlocked; $0.outcome = .notFound("staging.internal.example.com") }
    shot("6c-auto-long") { $0.state = .unlocked; $0.outcome = .auto("accounts.very-long-subdomain.enterprise-identity-provider.example.com") }
    shot("7-locked-pinned", false, true) { $0.state = .locked }
    shot("7b-unlocked-windows", false, true) {
        $0.state = .unlocked
        $0.keyCount = 14
        $0.windows = [AllowWindow(id: "a", kind: "git", title: "Git signing", sub: "Signin Key · zsh", until: Date().addingTimeInterval(1500), total: 3600),
                      AllowWindow(id: "b", kind: "git", title: "Git signing", sub: "Signin Key · zsh", until: Date().addingTimeInterval(900), total: 3600),
                      AllowWindow(id: "c", kind: "login", title: "git@github.com", sub: "Github Key · zsh", until: Date().addingTimeInterval(1200), total: 3600),
                      AllowWindow(id: "d", kind: "login", title: "root@203.0.113.7", sub: "Server Key · fish", until: Date().addingTimeInterval(240), total: 600)]
    }
    shot("7c-locked-error", false, true) { $0.state = .locked; $0.show("touchid_cancelled") }
    shot("1c-idle-stale") { $0.state = .unlocked; $0.keyCount = 14; $0.stale = true }
    shot("1d-idle-nokeys") { $0.state = .unlocked; $0.keyCount = 0; $0.show("keys_offline") }
    shot("8-unlocking") { $0.state = .locked; $0.unlocking = true }
    shot("9-offline") { $0.state = .offline("relay: connection refused") }
    shot("9b-relay-down", false, true) { $0.state = .unlocked; $0.relayNote = "relay disconnected, reconnecting" }
}

@main
enum Main {
    static let delegate = AppDelegate()
    static func main() {
        if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count {
            MainActor.assumeIsolated { snapshot(to: CommandLine.arguments[i + 1]) }
            return
        }
        // `nodwarden --tools`: which node/bw/bwbio would be run, to diagnose a refused path.
        if CommandLine.arguments.contains("--tools") {
            for (name, path) in [("node", Tools.node), ("bw", Tools.bw), ("bwbio", Tools.bwbio)] {
                print("\(name): \(path ?? Tools.problem(name) ?? "not found")")
            }
            print("PATH for children: \(Tools.childPath)")
            return
        }
        let app = NSApplication.shared
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
