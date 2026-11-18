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
    var body: some View {
        ZStack {
            Path { p in p.move(to: .init(x: 1, y: 0)); p.addLine(to: .init(x: 1, y: height)) }
                .stroke(t.line, style: StrokeStyle(lineWidth: 2, dash: dashed ? [5, 5] : []))
                .frame(width: 2, height: height)
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
let mark: NSImage = { let i = NSImage(contentsOfFile: "assets/mark-512.png")!; i.isTemplate = true; return i }()

struct Overview: View {
    let t: Theme
    var body: some View {
        VStack(spacing: 0) {
            Header(t: t, title: "NodWarden", subtitle: "One secret per request, released only with your nod")
                .padding(.bottom, 44)
            Text("AI AGENTS & SCRIPTS").font(.system(size: 14, weight: .bold)).tracking(1.2).foregroundStyle(t.sub)
                .padding(.bottom, 14)
            HStack(spacing: 30) {
                Card(t: t, icon: "sparkles", tint: violet, title: "Claude Code", subtitle: "Coding agent", pill: "Idle")
                Card(t: t, icon: "terminal", tint: orange, title: "Codex", subtitle: "Coding agent",
                     pill: "Requesting github.com", kind: .accent(blue))
                Card(t: t, icon: "gearshape", tint: green, title: "deploy.sh", subtitle: "Script", pill: "Idle")
            }
            FanIn(xs: [165, 525, 885]).stroke(t.line, lineWidth: 2).frame(width: 1050, height: 54)
            Card(t: t, icon: "lock", tint: teal, title: "Agent Access relay", subtitle: "End-to-end encrypted (Noise)",
                 pill: "Sees nothing", dashed: true, width: 380)
            VLine(t: t, height: 48, dashed: true)
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
                    Text("Waiting for your nod").font(.system(size: 13, weight: .semibold)).foregroundStyle(amber)
                        .padding(.horizontal, 12).padding(.vertical, 5).background(amber.opacity(0.14), in: Capsule())
                }
                Image(nsImage: island).resizable().scaledToFit()
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
            .padding(22)
            .frame(width: 620)
            .background(t.card, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(amber.opacity(0.55), lineWidth: 1.5))
            VLine(t: t, height: 54, label: "Touch ID")
            Card(t: t, icon: "shield.lefthalf.filled", tint: blue, title: "Bitwarden vault",
                 subtitle: "On your Mac", pill: "Releases one item, not the vault", width: 420)
        }
        .padding(.vertical, 64).padding(.horizontal, 60)
        .frame(width: 1170)
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
                        VLine(t: t, height: 44, label: "bwbio").frame(width: 340)
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

@MainActor func save<V: View>(_ v: V, _ name: String) {
    let r = ImageRenderer(content: v)
    r.scale = 2
    guard let img = r.nsImage, let tiff = img.tiffRepresentation,
          let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]) else {
        print("failed: \(name)"); return
    }
    try! png.write(to: URL(fileURLWithPath: "assets/\(name).png"))
    print("wrote assets/\(name).png")
}

MainActor.assumeIsolated {
    for dark in [true, false] {
        let t = Theme(dark: dark), s = dark ? "dark" : "light"
        save(Overview(t: t), "overview-\(s)")
        save(Architecture(t: t), "architecture-\(s)")
        save(Wordmark(t: t), "logo-\(s)")
    }
}
