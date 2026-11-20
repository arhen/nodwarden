import AppKit
import Combine
import LocalAuthentication
import SwiftUI

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

enum Mode: Equatable { case compact, result, expanded }

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
    var size: CGSize = .zero { didSet { if size != oldValue { onResize?() } } }
    /// The current screen's notch; updated when displays change (#17).
    @Published var notch = Notch.current
    var onResize: (() -> Void)?
    /// Set by the panel: a click landed outside the island, or Esc was pressed.
    @Published var dismissTick = 0
}

struct IslandView: View {
    @ObservedObject var core: Core
    @ObservedObject var layout: Layout
    @ObservedObject private var settings = Settings.shared
    @State private var hovering: Bool
    @State private var pinned: Bool
    @State private var minutes = 10
    @State private var confirming = false
    /// The live Touch ID prompt. Identified by its context, not the request id, so a
    /// cancelled prompt's late callback can't clear a newer one (#7).
    @State private var prompt: LAContext?
    /// When the request on screen was shown; Allow is ignored for a moment after a queue
    /// advance so one touch can't approve the next request by accident (#14).
    @State private var shownAt = Date.distantPast
    /// When the island last stopped showing a request. One that arrives right after waits
    /// for a click like a queued one: a requester that sends the next request the moment
    /// the first is answered (an SSH signature returns at once) must not find Touch ID
    /// armed again while your finger is still on the sensor (#14).
    @State private var clearedAt = Date.distantPast
    static let rearmDelay: TimeInterval = 2
    /// Request whose Touch ID just succeeded; drives the red fill.
    @State private var granted: Int?
    /// Shown under the buttons when Touch ID can't run (#28); cleared on the next attempt.
    @State private var touchIDProblem: String?

    /// Which status page shows when the island is open with no request.
    @State private var page: Page = .home
    /// The open panel's measured height; it sizes itself to what the page shows.
    @State private var panelHeight: CGFloat = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var notch: Notch { layout.notch }

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
        if core.outcome != nil { return .result }
        return .compact
    }

    /// Width of each "ear" flanking the notch. Always visible so the island
    /// reads as present even on a static hardware notch.
    var ear: CGFloat { hovering ? 78 : 64 }

    /// Height of the result row hanging below the notch.
    let resultRow: CGFloat = 48

    var size: CGSize {
        switch mode {
        case .compact: return CGSize(width: max(notch.width, 120) + ear * 2, height: notch.height)
        case .result: return CGSize(width: max(notch.width + 140, 360), height: notch.height + resultRow)
        case .expanded:
            if current != nil {
                return CGSize(width: max(notch.width + 200, 440),
                              height: notch.height + 106 + (touchIDProblem != nil ? 30 : 0))
            }
            return CGSize(width: max(notch.width + 240, 460), height: max(panelHeight, notch.height + 60))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            ZStack(alignment: .top) {
                IslandShape(top: 8, bottom: cornerRadius)
                    .fill(.black)
                    .shadow(color: .black.opacity(shadowOpacity), radius: 18, y: 8)

                // Clipped to the island: while it grows or shrinks, nothing shows outside it.
                content
                    .foregroundStyle(.white)
                    .padding(.horizontal, 8 + 14)
                    .frame(width: size.width, height: size.height, alignment: .top)
                    .clipShape(IslandShape(top: 8, bottom: cornerRadius))
            }
            .frame(width: size.width, height: size.height)
            .contentShape(Rectangle())
            .onHover { h in
                withAnimation(h ? springOpen : springClose) { hovering = h }
                if !h, pinned { collapseSoon() }
            }
            // Tapping opens the panel only from the small island. Once it's open, taps belong to
            // its buttons (End all, Lock, New agent token); it closes on an outside click, Esc or
            // when the pointer leaves.
            .gesture(mode == .expanded ? nil : TapGesture().onEnded {
                guard current == nil else { return }
                withAnimation(springOpen) { pinned = true }
            })
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .animation(reduceMotion ? .easeOut(duration: 0.18) : (mode == .compact ? springClose : springOpen), value: mode)
        .animation(reduceMotion ? .easeOut(duration: 0.18) : springSwap, value: core.outcome)
        .animation(reduceMotion ? .easeOut(duration: 0.18) : springOpen, value: current?.id)
        .environment(\.colorScheme, .dark)
        .onAppear { layout.size = size }
        .onChange(of: size) { _, s in layout.size = s }
        .onChange(of: layout.dismissTick) { _, _ in
            if pinned { withAnimation(springClose) { pinned = false } }
        }
        .onChange(of: pinned) { _, p in
            guard !p else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) {
                if !pinned { var t = Transaction(); t.disablesAnimations = true; withTransaction(t) { page = .home } }
            }
        }
        // A new token is shown once: keep the panel open on it.
        .onChange(of: core.token) { _, t in if t != nil, current == nil { withAnimation(springOpen) { pinned = true } } }
        .onChange(of: current?.id) { old, id in
            cancelPrompt()
            shownAt = Date()
            if old != nil, id == nil { clearedAt = Date() }
            // Arm Touch ID by itself only when the island has been empty for a moment. After a
            // queue advance the next request waits for a click, so two touches can't release
            // two things (#14).
            if old == nil, let id, Settings.shared.autoTouchID, Date().timeIntervalSince(clearedAt) > Self.rearmDelay,
               let r = core.queue.first(where: { $0.id == id }) {
                approve(r, minutes: nil, auto: true)
            }
        }
    }

    func cancelPrompt() {
        prompt?.invalidate()
        prompt = nil
        confirming = false
        granted = nil
        touchIDProblem = nil
    }

    /// Status panel folds back once the pointer has been away for a moment. Not on a page you
    /// are working in (typing a name, confirming, a token to copy): those close on Esc, an
    /// outside click or their own buttons.
    func collapseSoon() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            guard !hovering, pinned, [.home, .agents, .history, .settings].contains(page), core.token == nil else { return }
            withAnimation(springClose) { pinned = false }
        }
    }

    @ViewBuilder var content: some View {
        switch mode {
        case .compact:
            compact.frame(height: notch.height)
        case .result:
            if let o = core.outcome { resultView(o) }
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
        // The ears come back once the panel has mostly folded, and leave at once when it opens,
        // so they never show on top of the panel's content.
        .transition(.asymmetric(
            insertion: .opacity.animation(.easeOut(duration: 0.18).delay(0.16)),
            removal: .opacity.animation(.easeOut(duration: 0.08))
        ))
    }

    /// The brand mark always holds the left ear; state lives on the right.
    var leadingGlyph: some View {
        Mark(size: 18)
            .opacity(core.state == .unlocked ? 1 : 0.55)
            .symbolEffect(.pulse, isActive: core.unlocking)
            .accessibilityLabel("NodWarden, \(stateLabel)")
    }

    var cornerRadius: CGFloat {
        switch mode {
        case .compact: return 12
        case .result: return 20
        case .expanded: return 30
        }
    }

    var shadowOpacity: Double {
        switch mode {
        case .compact: return 0
        case .result: return 0.35
        case .expanded: return 0.45
        }
    }

    /// Identity for the right ear's content, so each change gets its own transition.
    var trailingKey: String { core.opening ? "opening" : core.unlocking ? "unlocking" : "state" }

    @ViewBuilder var trailingGlyph: some View {
        ZStack {
            trailingContent
                .id(trailingKey)
                .transition(reduceMotion ? .opacity : .blurSwap(y: 4))
        }
        .animation(reduceMotion ? .easeOut(duration: 0.15) : springSwap, value: trailingKey)
    }

    @ViewBuilder var trailingContent: some View {
        if core.opening {
            // Touch ID went through: the lock opens at once, green, breathing until the vault is ready.
            Image(systemName: "lock.open.fill").font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.green).symbolEffect(.pulse)
        } else if core.unlocking {
            Image(systemName: "touchid").font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.pink).symbolEffect(.pulse)
        } else {
            Image(systemName: lockSymbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(stateColor)
                .modifier(SymbolSwap())
                .animation(springSwap, value: lockSymbol)
                // Something to look at in the panel (a notice, or working from the offline copy).
                .overlay(alignment: .topTrailing) {
                    if core.notice != nil || core.stale {
                        Circle().fill(core.notice?.tone == .error ? Tint.bad : Tint.warn)
                            .frame(width: 6, height: 6)
                            .overlay(Circle().stroke(.black, lineWidth: 1.5))
                            .offset(x: 4, y: -3)
                            .transition(.scale.combined(with: .opacity))
                    }
                }
                .animation(springSwap, value: core.notice != nil || core.stale)
        }
    }

    func resultStyle(_ o: Outcome) -> (icon: String, color: Color, title: String, label: String) {
        switch o {
        case .approved(let d): return ("checkmark.circle.fill", .green, "Released", d)
        case .auto(let d): return ("checkmark.circle.fill", .green, "Allowed (auto)", d)
        case .denied(let d): return ("xmark.circle.fill", .red, "Denied", d)
        case .expired(let d): return ("xmark.circle.fill", .red, "Timed out", d)
        case .cancelled(let d): return ("xmark.circle.fill", .red, "Cancelled", d)
        case .notFound(let d): return ("exclamationmark.circle.fill", .orange, "No match", d)
        case .locked(let d): return ("exclamationmark.circle.fill", .orange, "Vault locked", d)
        case .offline(let d): return ("icloud.slash", .orange, "Refused offline", d)
        }
    }

    /// One row under the notch: icon, short verdict, then the item it concerned.
    func resultView(_ o: Outcome) -> some View {
        let s = resultStyle(o)
        return HStack(spacing: 8) {
            Image(systemName: s.icon)
                .font(.system(size: 17, weight: .semibold))
                .symbolRenderingMode(.palette)
                .foregroundStyle(.white, s.color)
            Text(s.title)
                .font(.system(size: 14, weight: .semibold))
                .fixedSize()
            if !s.label.isEmpty {
                Text(s.label)
                    .font(.system(size: 13))
                    .foregroundStyle(.white.opacity(0.6))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .frame(maxWidth: .infinity)
        .frame(height: resultRow - 4)
        .padding(.top, notch.height)
        .id(o)
        .transition(reduceMotion ? .opacity : .blurSwap(y: -6).animation(springOpen.delay(0.04)))
        .accessibilityElement(children: .combine)
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
                    Monogram(text: r.title)
                }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        // user@host: when it doesn't fit, cut the user, never the verified host.
                        MaskedText(text: r.title, masked: Settings.shared.maskRequests && r.ssh?.purpose != "git signing")
                            .font(.system(size: 15, weight: .semibold)).lineLimit(1)
                            .truncationMode(r.ssh?.purpose == "login" ? .head : .tail)
                        if core.queue.count > 1 {
                            Text("+\(core.queue.count - 1)")
                                .font(.system(size: 11, weight: .bold))
                                .contentTransition(.numericText(value: Double(core.queue.count)))
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background(.white.opacity(0.14), in: Capsule())
                                .transition(.blurSwap())
                        }
                    }
                    Text(r.ssh == nil ? "\(r.detail)  ·  → \(r.device)" : r.detail)
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
                // Offered only when the core would remember it: logins and git commit signing by
                // a local program. Never for unverified data or a forwarded request.
                if Settings.shared.offerWindows && (r.ssh?.canRemember ?? true) {
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
                        // The duration can't change while Touch ID is up: what you touch for is
                        // what was on screen when the prompt opened (#25).
                        .disabled(confirming)
                        .accessibilityLabel("Change auto-allow duration")
                    }
                    .background(.white.opacity(0.14), in: Capsule())
                }
                AllowButton(waiting: confirming, filled: granted == r.id) { approve(r, minutes: nil) }
            }
            if let why = touchIDProblem {
                Text(why)
                    .font(.system(size: 11))
                    .foregroundStyle(.orange.opacity(0.9))
                    .lineLimit(2)
                    .transition(.blurSwap(y: -4))
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
        PanelView(core: core, page: $page)
            .padding(.top, notch.height + 10)
            .padding(.bottom, 18)
            .padding(.horizontal, 4)
            .fixedSize(horizontal: false, vertical: true)
            .background(GeometryReader { g in
                Color.clear
                    .onAppear { panelHeight = g.size.height }
                    // A page change inside the panel resizes the island with the same spring
                    // as the content swap, instead of jumping.
                    .onChange(of: g.size.height) { _, h in
                        withAnimation(reduceMotion ? .easeOut(duration: 0.15) : springSwap) { panelHeight = h }
                    }
            })
            .transition(.asymmetric(
                insertion: .opacity.animation(springOpen.delay(0.06)),
                removal: .opacity.animation(.easeOut(duration: 0.1))
            ))
    }

    /// How long a Touch ID approval lasts, for the prompt: ", this time only" or
    /// " for the next 10 minutes (until 23:16), without asking again".
    func duration(_ m: Int?) -> String {
        guard let m else { return ", this time only" }
        let until = Date().addingTimeInterval(Double(m) * 60).formatted(date: .omitted, time: .shortened)
        return " for the next \(m) minutes (until \(until)), without asking again"
    }

    /// `auto` is the prompt that starts by itself when a request appears; anything else is a click.
    func approve(_ r: CredRequest, minutes m: Int?, auto: Bool = false) {
        guard !confirming else { return }
        // A click right after the request changed was meant for the previous one (#14).
        guard auto || Date().timeIntervalSince(shownAt) > 0.6 else { return }
        confirming = true
        var what: String
        if let s = r.ssh {
            let target: String
            switch s.purpose {
            case "login": target = "log in to \(r.title) with \(s.key)"
            case "git signing": target = m == nil ? "sign a git commit with \(s.key)" : "sign git commits with \(s.key)"
            case "unverified data": target = "sign unverified data with \(s.key)"
            default: target = "use \(s.key) for \(s.purpose)"
            }
            // A forwarded request was made on the other host; the local program only relays it.
            let who = s.via.map { "a program on \($0)" } ?? s.app
            what = "let \(who) \(target)" + duration(m)
        } else {
            what = m == nil ? "release \(r.title) to \(r.device)" + duration(nil)
                            : "allow \(r.title) for \(r.device)" + duration(m)
        }
        let ctx = LAContext()
        prompt = ctx
        touchIDProblem = nil
        if Settings.shared.maskRequests, r.ssh?.purpose != "git signing" {
            what = what.replacingOccurrences(of: r.title, with: MaskedText.hint(r.title))
        }
        // The window length is fixed now; the prompt text already names it (#25).
        let frozenMinutes = m
        confirmPresence(ctx, what) { ok, problem in
            // Ignore a stale answer: this exact prompt was cancelled or replaced meanwhile (#7).
            guard prompt === ctx else { return }
            prompt = nil
            confirming = false
            if let problem { withAnimation(springSwap) { touchIDProblem = problem } }
            guard ok, core.queue.contains(where: { $0.id == r.id }) else { return }
            let m = frozenMinutes
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
    }


    var lockSymbol: String { core.lockSymbol }
    var stateColor: Color { core.stateColor }
    var stateLabel: String { core.stateLabel }
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

/// First letter of the item name. No network fetch: a remote icon service would learn
/// which site's secret you're approving, and when (#10).
struct Monogram: View {
    let text: String
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 9, style: .continuous).fill(.white.opacity(0.12))
            Text(text.first.map { String($0).uppercased() } ?? "?")
                .font(.system(size: 17, weight: .bold, design: .rounded))
        }
        .frame(width: 36, height: 36)
    }
}

/// Lock ↔ unlock morph. `.replace.magic` exists from macOS 15; older systems get a plain replace (#11).
struct SymbolSwap: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 15, *) {
            content.contentTransition(.symbolEffect(.replace.magic(fallback: .downUp.byLayer)))
        } else {
            content.contentTransition(.symbolEffect(.replace))
        }
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
    enum Kind { case primary, quiet, danger }
    static let dangerText = Color(red: 1, green: 0.45, blue: 0.45)
    let kind: Kind
    var flat = false
    var compact = false
    var height: CGFloat = 30
    init(_ kind: Kind, flat: Bool = false, compact: Bool = false, height: CGFloat = 30) {
        self.kind = kind; self.flat = flat; self.compact = compact; self.height = height
    }

    var fill: Color {
        switch kind {
        case .primary: return .white
        case .quiet: return .white.opacity(0.14)
        case .danger: return .red.opacity(0.18)
        }
    }

    func makeBody(configuration c: Configuration) -> some View {
        c.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(kind == .primary ? Color.black : (kind == .danger ? Pill.dangerText : .white))
            .padding(.leading, compact ? 4 : 16)
            .padding(.trailing, compact ? 12 : (flat ? 6 : 16))
            .frame(height: height)
            .background(flat ? Color.clear : fill, in: Capsule())
            .opacity(c.isPressed ? 0.8 : 1)
            .scaleEffect(c.isPressed ? 0.96 : 1)
            .animation(.easeOut(duration: 0.1), value: c.isPressed)
            .contentShape(Capsule())
    }
}
