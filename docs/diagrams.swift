// Renders the README artwork in dark and light: `swift docs/diagrams.swift` from the repo root.
import AppKit
import SwiftUI

struct Theme {
    let dark: Bool
    var bg: Color { dark ? Color(red: 0.05, green: 0.07, blue: 0.09) : Color(red: 0.98, green: 0.98, blue: 0.99) }
    var card: Color { dark ? Color(red: 0.08, green: 0.10, blue: 0.12) : .white }
    var border: Color { dark ? .white.opacity(0.13) : .black.opacity(0.10) }
    var text: Color { dark ? .white : Color(white: 0.08) }
    var sub: Color { dark ? .white.opacity(0.58) : .black.opacity(0.5) }
    var pill: Color { dark ? .white.opacity(0.08) : .black.opacity(0.05) }
    var line: Color { dark ? .white.opacity(0.22) : .black.opacity(0.2) }
    var section: Color { dark ? Color(red: 0.2, green: 0.75, blue: 0.8).opacity(0.45) : Color(red: 0.05, green: 0.55, blue: 0.62).opacity(0.5) }
    var sectionText: Color { dark ? Color(red: 0.35, green: 0.85, blue: 0.9) : Color(red: 0.03, green: 0.5, blue: 0.58) }
}

enum PillKind { case plain, accent(Color) }

struct Card: View {
    let t: Theme
    let icon: String
    let tint: Color
    let title: String
    let subtitle: String
    var pill: String? = nil
    var kind: PillKind = .plain
    var dashed = false
    var width: CGFloat = 330
    var mono = false

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous).fill(tint.opacity(t.dark ? 0.16 : 0.12))
                Image(systemName: icon).font(.system(size: 22, weight: .semibold)).foregroundStyle(tint)
            }
            .frame(width: 52, height: 52)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 20, weight: .bold)).foregroundStyle(t.text)
                Text(subtitle).font(.system(size: 15)).foregroundStyle(t.sub).fixedSize(horizontal: false, vertical: true)
                if let pill { pillView(pill).padding(.top, 8) }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(width: width, alignment: .leading)
        .background(t.card, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(t.border, style: StrokeStyle(lineWidth: 1.5, dash: dashed ? [6, 5] : []))
        )
    }

    func pillView(_ s: String) -> some View {
        let fg: Color, bg: Color
        switch kind {
        case .plain: fg = t.text.opacity(0.85); bg = t.pill
        case .accent(let c): fg = c; bg = c.opacity(t.dark ? 0.14 : 0.1)
        }
        return Text(s)
            .font(mono ? .system(size: 13, weight: .medium, design: .monospaced) : .system(size: 13, weight: .semibold))
            .foregroundStyle(fg)
            .padding(.horizontal, 12).padding(.vertical, 5)
            .frame(maxWidth: .infinity)
            .background(bg, in: Capsule())
    }
}

struct VLine: View {
    let t: Theme
    var height: CGFloat = 44
    var dashed = false
    var label: String? = nil
    var color: Color? = nil
    /// 0...1 position of a travelling dot, nil = no dot.
    var dot: CGFloat? = nil
    var dotColor: Color = .blue
    var body: some View {
        ZStack {
            Path { p in p.move(to: .init(x: 1, y: 0)); p.addLine(to: .init(x: 1, y: height)) }
                .stroke(color ?? t.line, style: StrokeStyle(lineWidth: 2, dash: dashed ? [5, 5] : []))
                .frame(width: 2, height: height)
            if let dot {
                Circle().fill(dotColor).frame(width: 12, height: 12)
                    .shadow(color: dotColor.opacity(0.8), radius: 6)
                    .offset(y: (dot - 0.5) * height)
            }
            if let label {
                Text(label).font(.system(size: 12, weight: .semibold)).foregroundStyle(t.sub)
                    .padding(.horizontal, 8).padding(.vertical, 2)
                    .background(t.bg)
            }
        }
    }
}

/// Lines from three card centers down into one point.
struct FanIn: Shape {
    let xs: [CGFloat]
    func path(in r: CGRect) -> Path {
        var p = Path()
        let mid = r.midX, y = r.height * 0.5, rad: CGFloat = 16
        for x in xs {
            p.move(to: .init(x: x, y: 0))
            if abs(x - mid) < 1 { p.addLine(to: .init(x: x, y: r.height)); continue }
            p.addLine(to: .init(x: x, y: y - rad))
            let dir: CGFloat = x < mid ? 1 : -1
            p.addQuadCurve(to: .init(x: x + dir * rad, y: y), control: .init(x: x, y: y))
            p.addLine(to: .init(x: mid - dir * rad, y: y))
            p.addQuadCurve(to: .init(x: mid, y: y + rad), control: .init(x: mid, y: y))
            p.addLine(to: .init(x: mid, y: r.height))
        }
        return p
    }
}

struct SectionBox<C: View>: View {
    let t: Theme
    let label: String
    @ViewBuilder let content: C
    var body: some View {
        content
            .padding(.horizontal, 28).padding(.top, 38).padding(.bottom, 26)
            .overlay(
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .strokeBorder(t.section, style: StrokeStyle(lineWidth: 1.5, dash: [7, 6]))
            )
            .overlay(alignment: .topLeading) {
                Text(label).font(.system(size: 14, weight: .bold)).tracking(1.2).foregroundStyle(t.sectionText)
                    .padding(.horizontal, 8).background(t.bg).offset(x: 22, y: -9)
            }
    }
}

struct Header: View {
    let t: Theme
    let title: String
    let subtitle: String
    var body: some View {
        VStack(spacing: 10) {
            Text(title).font(.system(size: 38, weight: .heavy)).tracking(-0.6).foregroundStyle(t.text)
            Text(subtitle).font(.system(size: 18)).foregroundStyle(t.sub)
        }
    }
}

let violet = Color(red: 0.45, green: 0.4, blue: 0.95)
let orange = Color(red: 0.95, green: 0.45, blue: 0.15)
let green = Color(red: 0.12, green: 0.65, blue: 0.35)
let blue = Color(red: 0.12, green: 0.5, blue: 0.95)
let amber = Color(red: 0.92, green: 0.62, blue: 0.05)
let teal = Color(red: 0.08, green: 0.62, blue: 0.68)

let island = NSImage(contentsOfFile: "assets/states/3-request.png")!
let islandFull = [
    "idle": NSImage(contentsOfFile: "assets/states/full/idle.png")!,
    "request": NSImage(contentsOfFile: "assets/states/full/request.png")!,
    "approved": NSImage(contentsOfFile: "assets/states/full/approved.png")!,
]

/// The overview story, in seconds. One loop = `Story.length`.
enum Story {
    static let length: Double = 9.0
    // Phases: idle, codex asks, line to relay, relay to notch, island opens, nod, dot back down, released, settle.
    static func phase(_ s: Double) -> (name: String, k: Double) {
        let marks: [(String, Double)] = [
            ("idle", 0.0), ("ask", 0.9), ("toRelay", 1.5), ("toNotch", 2.3), ("open", 3.1),
            ("nod", 5.1), ("toVault", 5.9), ("back", 6.6), ("done", 7.6), ("end", Story.length),
        ]
        for i in 0..<(marks.count - 1) where s >= marks[i].1 && s < marks[i + 1].1 {
            return (marks[i].0, (s - marks[i].1) / (marks[i + 1].1 - marks[i].1))
        }
        return ("done", 1)
    }
}

func ease(_ x: Double) -> CGFloat { CGFloat(1 - pow(1 - min(max(x, 0), 1), 3)) }
let mark: NSImage = { let i = NSImage(contentsOfFile: "assets/mark-512.png")!; i.isTemplate = true; return i }()

struct Overview: View {
    let t: Theme
    /// Seconds into the story; nil renders the static poster.
    var time: Double? = nil

    var ph: (name: String, k: Double) { time.map(Story.phase) ?? ("open", 1) }
    func after(_ names: String...) -> Bool { names.contains(ph.name) }
    var asking: Bool { !after("idle") }
    var granted: Bool { after("nod", "toVault", "back", "done") }
    var lineTint: Color { granted ? green : blue }

    var codexPill: (String, PillKind) {
        switch ph.name {
        case "idle": return ("Idle", .plain)
        case "done": return ("Got github.com ✓", .accent(green))
        case "back": return ("Receiving…", .accent(green))
        default: return ("Requesting github.com", .accent(blue))
        }
    }
    var relayPill: (String, PillKind) {
        switch ph.name {
        case "toRelay", "toNotch": return ("Relaying (encrypted)…", .accent(blue))
        case "back": return ("Relaying (encrypted)…", .accent(green))
        default: return ("Sees nothing", .plain)
        }
    }
    var notchState: (String, Color) {
        switch ph.name {
        case "idle", "ask", "toRelay", "toNotch": return ("Idle", t.sub)
        case "open": return ("Waiting for your nod", amber)
        case "nod": return ("Touch ID ✓", green)
        default: return ("Released ✓", green)
        }
    }
    var islandImage: NSImage {
        guard time != nil else { return island }
        switch ph.name {
        case "idle", "ask", "toRelay", "toNotch": return islandFull["idle"]!
        case "open", "nod": return islandFull["request"]!
        default: return islandFull["approved"]!
        }
    }
    /// The island grows with its content, like the real one.
    var islandHeight: CGFloat {
        guard time != nil else { return 160 }
        switch ph.name {
        case "open": return 46 + 114 * ease(ph.k * 2.5)
        case "nod": return 160
        case "toVault": return 160 - 114 * ease(ph.k * 1.5)
        default: return 46
        }
    }
    var vaultPill: (String, PillKind) {
        switch ph.name {
        case "toVault": return ("Looking up github.com…", .accent(blue))
        case "back", "done": return ("Released 1 item ✓", .accent(green))
        default: return ("Releases one item, not the vault", .plain)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Header(t: t, title: "NodWarden", subtitle: "One secret per request, released only with your nod")
                .padding(.bottom, 44)
            Text("AI AGENTS & SCRIPTS").font(.system(size: 14, weight: .bold)).tracking(1.2).foregroundStyle(t.sub)
                .padding(.bottom, 14)
            HStack(spacing: 30) {
                Card(t: t, icon: "sparkles", tint: violet, title: "Claude Code", subtitle: "Coding agent", pill: "Idle")
                Card(t: t, icon: "terminal", tint: orange, title: "Codex", subtitle: "Coding agent",
                     pill: codexPill.0, kind: codexPill.1)
                    .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .strokeBorder(after("done") ? green : .clear, lineWidth: 2))
                Card(t: t, icon: "gearshape", tint: green, title: "deploy.sh", subtitle: "Script", pill: "Idle")
            }
            ZStack {
                FanIn(xs: [165, 525, 885]).stroke(t.line, lineWidth: 2)
                FanIn(xs: [525]).stroke(asking ? lineTint : .clear, lineWidth: 2)
                if after("ask") || (after("back") && ph.k >= 0.5) {
                    let k = after("ask") ? ease(ph.k) : 1 - ease((ph.k - 0.5) * 2)
                    Circle().fill(lineTint).frame(width: 12, height: 12).shadow(color: lineTint.opacity(0.8), radius: 6)
                        .position(x: 525, y: 54 * k)
                }
            }
            .frame(width: 1050, height: 54)
            Card(t: t, icon: "lock", tint: teal, title: "Agent Access relay", subtitle: "End-to-end encrypted (Noise)",
                 pill: relayPill.0, kind: relayPill.1, dashed: true, width: 380)
            VLine(t: t, height: 48, dashed: true, color: asking && !after("ask", "toRelay") ? lineTint : nil,
                  dot: after("toNotch") ? ease(ph.k) : (after("back") && ph.k < 0.5 ? 1 - ease(ph.k * 2) : nil),
                  dotColor: lineTint)
            VStack(spacing: 16) {
                HStack(spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12, style: .continuous).fill(t.text.opacity(t.dark ? 0.12 : 0.9))
                        Image(nsImage: mark).resizable().scaledToFit().padding(10)
                            .foregroundStyle(t.dark ? .white : .white)
                    }
                    .frame(width: 52, height: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("NodWarden").font(.system(size: 20, weight: .bold)).foregroundStyle(t.text)
                        Text("Grows out of your MacBook's notch").font(.system(size: 15)).foregroundStyle(t.sub)
                    }
                    Spacer()
                    Text(notchState.0).font(.system(size: 13, weight: .semibold)).foregroundStyle(notchState.1)
                        .padding(.horizontal, 12).padding(.vertical, 5).background(notchState.1.opacity(0.14), in: Capsule())
                }
                Image(nsImage: islandImage).resizable().scaledToFill()
                    .frame(width: 576, height: islandHeight, alignment: .top)
                    .clipped()
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(alignment: .bottomTrailing) {
                        if after("nod") {
                            Image(systemName: "touchid").font(.system(size: 34, weight: .semibold))
                                .foregroundStyle(Color(red: 0.95, green: 0.3, blue: 0.5))
                                .padding(10).background(.black.opacity(0.6), in: Circle())
                                .scaleEffect(0.8 + 0.2 * ease(ph.k * 2))
                                .padding(14)
                        }
                    }
            }
            .padding(22)
            .frame(width: 620)
            .background(t.card, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(time == nil || after("open", "nod") ? amber.opacity(0.7) : (granted ? green.opacity(0.6) : t.border),
                              lineWidth: 1.5))
            VLine(t: t, height: 54, label: "Touch ID", color: granted ? green : nil,
                  dot: after("toVault") ? ease(ph.k) : nil, dotColor: green)
            Card(t: t, icon: "shield.lefthalf.filled", tint: blue, title: "Bitwarden vault",
                 subtitle: "On your Mac", pill: vaultPill.0, kind: vaultPill.1, width: 420)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 64).padding(.horizontal, 60)
        .frame(width: 1170, height: 1090, alignment: .top)
        .background(t.bg)
    }
}

struct Architecture: View {
    let t: Theme
    var body: some View {
        VStack(spacing: 0) {
            Header(t: t, title: "NodWarden — Architecture", subtitle: "Who talks to whom, and over which channel")
                .padding(.bottom, 48)
            SectionBox(t: t, label: "AGENT SIDE") {
                Card(t: t, icon: "terminal", tint: orange, title: "aac run", subtitle: "Any agent or script",
                     pill: "aac run --domain github.com", width: 420, mono: true)
                    .frame(width: 900)
            }
            VLine(t: t, height: 50, dashed: true)
            Card(t: t, icon: "lock", tint: teal, title: "Relay", subtitle: "Zero-knowledge, Noise E2E, PSK-paired",
                 pill: "ap-proxy", dashed: true, width: 420, mono: true)
            VLine(t: t, height: 50, dashed: true)
            SectionBox(t: t, label: "YOUR MAC") {
                VStack(spacing: 0) {
                    HStack(alignment: .center, spacing: 0) {
                        Card(t: t, icon: "hand.raised.fill", tint: amber, title: "NodWarden.app",
                             subtitle: "Notch UI · Touch ID on Allow", pill: "decide()", width: 340, mono: true)
                        VStack(spacing: 6) {
                            arrow("stdin: decisions, session", right: true)
                            arrow("stdout: metadata, no secrets", right: false)
                        }
                        .frame(width: 220)
                        Card(t: t, icon: "point.3.connected.trianglepath.dotted", tint: teal, title: "aac-core",
                             subtitle: "ap-client UserClient", pill: "on_credential_request()", width: 340, mono: true)
                    }
                    HStack(spacing: 0) {
                        VLine(t: t, height: 44, label: "bw or bwbio").frame(width: 340)
                        Spacer().frame(width: 220)
                        VLine(t: t, height: 44, label: "BW_SESSION in child env").frame(width: 340)
                    }
                    HStack(spacing: 220) {
                        Card(t: t, icon: "touchid", tint: Color(red: 0.9, green: 0.25, blue: 0.45), title: "Bitwarden Desktop",
                             subtitle: "Touch ID unlock, once per login", width: 340)
                        Card(t: t, icon: "shield.lefthalf.filled", tint: blue, title: "bw + vault",
                             subtitle: "One item per approved request", pill: "bw get item", width: 340, mono: true)
                    }
                }
            }
        }
        .padding(.vertical, 64).padding(.horizontal, 60)
        .frame(width: 1170)
        .background(t.bg)
    }

    func arrow(_ label: String, right: Bool) -> some View {
        VStack(spacing: 3) {
            Text(label).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(t.sub)
            HStack(spacing: 0) {
                if !right { Image(systemName: "arrowtriangle.left.fill").font(.system(size: 9)).foregroundStyle(t.line) }
                Rectangle().fill(t.line).frame(height: 2)
                if right { Image(systemName: "arrowtriangle.right.fill").font(.system(size: 9)).foregroundStyle(t.line) }
            }
        }
        .padding(.horizontal, 10)
    }
}

struct Wordmark: View {
    let t: Theme
    var body: some View {
        HStack(spacing: 26) {
            Image(nsImage: mark).resizable().scaledToFit().frame(width: 150, height: 150)
                .foregroundStyle(t.dark ? .white : Color(white: 0.08))
            HStack(spacing: 0) {
                Text("Nod").foregroundStyle(amber)
                Text("Warden").foregroundStyle(t.dark ? .white : Color(white: 0.08))
            }
            .font(.system(size: 120, weight: .heavy)).tracking(-2)
        }
        .padding(30)
    }
}

@MainActor func save<V: View>(_ v: V, _ name: String, scale: CGFloat = 2) {
    let r = ImageRenderer(content: v)
    r.scale = scale
    guard let img = r.nsImage, let tiff = img.tiffRepresentation,
          let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]) else {
        print("failed: \(name)"); return
    }
    try! png.write(to: URL(fileURLWithPath: name.hasPrefix("/") ? "\(name).png" : "assets/\(name).png"))
    if !name.hasPrefix("/") { print("wrote assets/\(name).png") }
}

/// Frames for the animated overview; docs/animate.sh stitches them into WebP.
@MainActor func frames(dark: Bool, fps: Double, dir: String) {
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let n = Int(Story.length * fps)
    for i in 0..<n {
        save(Overview(t: Theme(dark: dark), time: Double(i) / fps), String(format: "%@/f%04d", dir, i), scale: 1.5)
    }
    print("wrote \(n) frames to \(dir)")
}

MainActor.assumeIsolated {
    if let i = CommandLine.arguments.firstIndex(of: "--frames") {
        let dark = CommandLine.arguments[i + 1] == "dark"
        frames(dark: dark, fps: 24, dir: CommandLine.arguments[i + 2])
        return
    }
    for dark in [true, false] {
        let t = Theme(dark: dark), s = dark ? "dark" : "light"
        save(Overview(t: t), "overview-\(s)")
        save(Architecture(t: t), "architecture-\(s)")
        save(Wordmark(t: t), "logo-\(s)")
    }
}
