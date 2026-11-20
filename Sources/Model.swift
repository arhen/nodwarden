import AppKit
import Combine
import LocalAuthentication
import SwiftUI

// MARK: - Core bridge

struct CredRequest: Identifiable, Equatable {
    let id: Int
    /// What the request is for, as the user should read it: the item's own name for
    /// credentials (#15), the verified host for SSH logins.
    let title: String
    /// Second line: username, host, "requested by id", etc.
    let detail: String
    let device: String
    let arrived: Date
    let timeout: Double
    var ssh: SSHInfo? = nil
}

struct SSHInfo: Equatable {
    let key: String
    let purpose: String
    /// Executable name from the kernel, a hint: the requester can't fake its path,
    /// but it can still be any program you run.
    let app: String
    /// Set when the request was forwarded from another host (`ssh -A`): it was made
    /// there, not by `app`.
    var via: String? = nil
    /// Whether the core would remember an "Allow N minutes" for this request.
    var canRemember = true
}

/// An open Allow window, as the core reports it (#5).
struct AllowWindow: Identifiable, Equatable {
    let id: String
    /// "login", "git", "secret" or "other".
    let kind: String
    let title: String
    let sub: String
    let until: Date
    let total: Double
}

/// One finished request, for the History tab. Memory only: it names hosts, items and
/// usernames, which Bitwarden keeps encrypted on disk, so it is never written anywhere.
struct HistoryEntry: Identifiable, Equatable {
    enum Result: String { case allowed, auto, denied, expired, cancelled, notFound, locked }
    let id: Int
    /// "login", "git", "secret" or "other".
    let kind: String
    let title: String
    let sub: String
    let result: Result
    var at: Date
    /// Back-to-back repeats folded into this row (auto and locked only).
    var count = 1
}

/// A device that paired with a token, or a token no device has used yet (#3).
struct Agent: Identifiable, Equatable {
    let id: String
    let name: String?
    /// Paired / created, and last connected (devices only).
    let since: Date
    var seen: Date? = nil
    /// Tokens: the device seen using it, if NodWarden has recorded one.
    var usedBy: String? = nil
    /// "Unnamed · 7f3a9c" for the ones made before naming existed.
    var label: String { name ?? "Unnamed · \(id.prefix(6))" }
}

/// Something the panel tells you, worded here, never raw tool output. `retry`: the card offers
/// one, and what it does.
struct Notice: Equatable, Identifiable {
    enum Tone { case info, warning, error }
    enum Retry: Equatable { case unlock, refresh }
    let id: String
    let tone: Tone
    let symbol: String
    let title: String
    let detail: String
    var retry: Retry? = nil

    /// Words for every code the core or the app reports. Unknown codes get a general one.
    static func of(_ code: String) -> Notice {
        switch code {
        case "offline":
            return Notice(id: code, tone: .warning, symbol: "icloud.slash",
                          title: "Vault server unreachable",
                          detail: "Using the copy on this Mac. Changes made elsewhere show up once it's back.",
                          retry: .refresh)
        case "login":
            return Notice(id: code, tone: .error, symbol: "person.crop.circle.badge.exclamationmark",
                          title: "Bitwarden needs you to log in again",
                          detail: "Run bw login in a terminal, then unlock.", retry: .unlock)
        case "timeout":
            return Notice(id: code, tone: .warning, symbol: "hourglass",
                          title: "The vault took too long to answer",
                          detail: "Using what was already loaded.", retry: .refresh)
        case "keys_offline":
            return Notice(id: code, tone: .error, symbol: "key.slash",
                          title: "SSH keys couldn't be loaded",
                          detail: "The vault server is unreachable and there's no copy on this Mac yet.",
                          retry: .refresh)
        case "keys_failed":
            return Notice(id: code, tone: .error, symbol: "key.slash",
                          title: "SSH keys couldn't be loaded",
                          detail: "Bitwarden didn't return the vault. SSH and git signing won't work until it does.",
                          retry: .refresh)
        case "keys_none":
            return Notice(id: code, tone: .info, symbol: "key",
                          title: "No SSH keys in the vault",
                          detail: "Add an SSH key item in Bitwarden to use it here.", retry: .refresh)
        case "touchid_cancelled":
            return Notice(id: code, tone: .info, symbol: "touchid",
                          title: "Unlock cancelled", detail: "Nothing was unlocked.", retry: .unlock)
        case "desktop_unreachable":
            return Notice(id: code, tone: .error, symbol: "macwindow.badge.plus",
                          title: "Bitwarden Desktop isn't answering",
                          detail: "Open it and turn on unlock with Touch ID. If it's open, quit and reopen it.",
                          retry: .unlock)
        case "session_rejected", "bw_locked":
            return Notice(id: code, tone: .warning, symbol: "lock.trianglebadge.exclamationmark",
                          title: "The vault locked itself",
                          detail: "Bitwarden ended the session. Unlock again to continue.", retry: .unlock)
        case "tools_missing":
            return Notice(id: code, tone: .error, symbol: "wrench.and.screwdriver",
                          title: "Bitwarden CLI not found",
                          detail: "NodWarden needs node and bw. Install them, then reopen NodWarden.")
        case "lock_failed":
            return Notice(id: code, tone: .warning, symbol: "lock.trianglebadge.exclamationmark",
                          title: "Bitwarden didn't confirm the lock",
                          detail: "NodWarden forgot the session. Lock Bitwarden Desktop too to be sure.")
        case "core_restarted":
            return Notice(id: code, tone: .warning, symbol: "arrow.clockwise",
                          title: "NodWarden restarted its listener",
                          detail: "It stopped answering, so it was locked and started again.")
        case "agent_failed":
            return Notice(id: code, tone: .error, symbol: "terminal",
                          title: "The SSH agent couldn't start",
                          detail: "SSH logins and git signing won't go through NodWarden. Reopen it to try again.")
        case "flood":
            return Notice(id: code, tone: .warning, symbol: "exclamationmark.bubble",
                          title: "Too many requests at once",
                          detail: "An agent sent more than three; the extra ones were denied.")
        case "token_relay":
            return Notice(id: code, tone: .warning, symbol: "antenna.radiowaves.left.and.right.slash",
                          title: "Can't make a token right now",
                          detail: "Tokens need the Agent Access relay. Try again once it's connected.")
        case "token_failed":
            return Notice(id: code, tone: .error, symbol: "key.horizontal",
                          title: "The token wasn't made", detail: "The relay didn't answer in time. Try again.")
        case "pairings_failed":
            return Notice(id: code, tone: .error, symbol: "externaldrive.badge.exclamationmark",
                          title: "Couldn't update the agent list",
                          detail: "The pairing files in ~/.access-protocol couldn't be read or written.")
        case "rendezvous_refused":
            return Notice(id: code, tone: .info, symbol: "hand.raised",
                          title: "A pairing code was refused",
                          detail: "Something tried to pair without a token. Only tokens made here are accepted.")
        default:
            return Notice(id: code, tone: .warning, symbol: "exclamationmark.circle",
                          title: "Something went wrong", detail: "Details are in ~/Library/Logs/NodWarden.")
        }
    }
}

enum VaultState: Equatable { case starting, locked, unlocked, offline(String) }

enum Outcome: Hashable {
    case approved(String), denied(String), auto(String), expired(String), notFound(String), locked(String), cancelled(String)
}

/// Absolute tool paths, resolved once (#4). PATH is only used to find them; a path another
/// user could redirect is refused. Override the search with NODWARDEN_PATH.
/// Same rules as `resolve_trusted` in core/src/bw.rs.
