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

enum VaultState: Equatable { case starting, locked, unlocked, offline(String) }

enum Outcome: Hashable {
    case approved(String), denied(String), auto(String), expired(String), notFound(String), locked(String), cancelled(String)
}

/// Absolute tool paths, resolved once (#4). PATH is only used to find them; a path another
/// user could redirect is refused. Override the search with NODWARDEN_PATH.
/// Same rules as `resolve_trusted` in core/src/bw.rs.
