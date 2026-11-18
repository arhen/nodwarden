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

enum VaultState: Equatable { case starting, locked, unlocked, offline(String) }

enum Outcome: Hashable {
    case approved(String), denied(String), auto(String), expired(String), notFound(String), locked(String), cancelled(String)
}

/// Absolute tool paths, resolved once (#4). PATH is only used to find them; a path another
/// user could redirect is refused. Override the search with NODWARDEN_PATH.
/// Same rules as `resolve_trusted` in core/src/bw.rs.
