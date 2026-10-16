//! Pure policy for delegated permission answering (`docs/06-agentic-supervision.md`).
//!
//! Delegation lets a human arm one agent invocation so Uniterm itself answers
//! the provider's own permission prompt, typing the provider's approval reply
//! through the same guarded terminal-delivery path a human uses. It never
//! intercepts a tool call: the only side effect a positive verdict ever has is
//! those approval bytes, and every verdict is recorded in the event log before
//! anything is typed.
//!
//! This module is the pure decision engine, the sibling of `guardrail.rs`: no
//! I/O, no async, no provider ids. Deny wins at every step and any uncertainty
//! withholds, so configuration can only ever widen the allowlist, never narrow
//! the compiled-in deny floor.

use serde::{Deserialize, Serialize};

use crate::{PaneId, WaitingKind};

/// Hard bound on allowlist rules, so policy evaluation stays constant-time.
pub const DELEGATION_MAX_RULES: usize = 64;
/// Hard bound on the hourly auto-answer budget.
pub const DELEGATION_MAX_ANSWERS_PER_HOUR: u16 = 240;
/// Default hourly budget when the Workspace config does not set one.
pub const DELEGATION_DEFAULT_ANSWERS_PER_HOUR: u16 = 30;
/// Hard bound on one rule's config text.
pub const DELEGATION_MAX_RULE_BYTES: usize = 256;

/// Bounded facts one evaluation needs, all already owned by the server.
///
/// `tool` and `preview` come from the invocation-scoped
/// [`crate::AgentPermission`] payload, never from a free-text summary string,
/// and `project_root` is the canonical root of the pane's Project.
pub struct DelegationFacts<'a> {
    /// Anything but a permission prompt withholds by construction.
    pub kind: WaitingKind,
    /// The tool the provider's permission prompt asks about.
    pub tool: &'a str,
    /// The tool call's most identifying argument, bounded and control-free.
    pub preview: &'a str,
    /// Canonical root every path argument must stay inside.
    pub project_root: &'a str,
}

/// Pure outcome. There is deliberately no `Deny` verdict that types anything:
/// the supervisor only ever types an approval, and only on `Allow`.
/// `Withhold` leaves the waiting item untouched for the human and says why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DelegateVerdict {
    /// The prompt matches the allowlist and clears the deny floor.
    Allow,
    /// The prompt stays with the human; the reason is auditable.
    Withhold {
        /// Human-readable explanation, recorded in the event log.
        reason: String,
    },
}

/// One allowlist entry: a command name plus an optional argument prefix.
///
/// A rule with `arg_prefix` matches only invocations whose leading argument
/// words equal it exactly (word-boundary match), so `cargo test` never
/// legitimizes `cargo publish`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRule {
    /// Command name, or an exact path for a project-local program.
    pub program: String,
    /// Leading argument words the invocation must start with.
    pub arg_prefix: Option<String>,
}

impl CommandRule {
    /// Parse one `delegation-allow` config value: a command name followed by
    /// optional plain argument words. Anything the evaluation lexer could not
    /// split safely is rejected here so no rule is silently inert.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("delegation rule cannot be empty".into());
        }
        if text.len() > DELEGATION_MAX_RULE_BYTES {
            return Err(format!(
                "delegation rule is over {DELEGATION_MAX_RULE_BYTES} bytes"
            ));
        }
        // A tab is ordinary argument whitespace; every other control
        // character has no business in a command rule.
        if text
            .chars()
            .any(|character| character.is_control() && character != '\t')
        {
            return Err("delegation rule cannot contain control characters".into());
        }
        let mut parts = text.splitn(2, char::is_whitespace);
        let program = parts.next().unwrap_or_default().to_string();
        if program
            .chars()
            .any(|character| "\"'\\$`;&|<>".contains(character))
        {
            return Err("rule program must be a plain command name".into());
        }
        let arg_prefix = parts
            .next()
            .map(str::trim)
            .filter(|rest| !rest.is_empty())
            .map(str::to_string);
        if let Some(prefix) = &arg_prefix {
            if lex_command(prefix).is_none() {
                return Err("rule arguments must be plain shell words without operators".into());
            }
        }
        Ok(CommandRule {
            program,
            arg_prefix,
        })
    }

    /// The argument words this rule requires, lexed once per evaluation. A
    /// rule that cannot lex matches nothing; [`CommandRule::parse`] rejects
    /// such rules at the config boundary.
    fn prefix_words(&self) -> Option<Vec<String>> {
        match &self.arg_prefix {
            None => Some(Vec::new()),
            Some(prefix) => lex_command(prefix),
        }
    }
}

/// Workspace delegation policy after config parsing. The deny floor is
/// compiled into [`evaluate_delegation`] and cannot be narrowed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationPolicy {
    /// Allowlist of delegable commands; empty delegates nothing.
    pub allow: Vec<CommandRule>,
    /// Maximum auto-answers per armed Pane per hour before delegation
    /// disarms itself and hands every prompt back to the human.
    pub max_answers_per_hour: u16,
}

impl Default for DelegationPolicy {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            max_answers_per_hour: DELEGATION_DEFAULT_ANSWERS_PER_HOUR,
        }
    }
}

impl DelegationPolicy {
    /// Reject impossible durable values rather than silently changing an
    /// armed Pane's contract.
    pub fn validate(&self) -> Result<(), String> {
        if self.allow.len() > DELEGATION_MAX_RULES {
            return Err("delegation allowlist is outside its bounded size".into());
        }
        if !(1..=DELEGATION_MAX_ANSWERS_PER_HOUR).contains(&self.max_answers_per_hour) {
            return Err("max answers per hour is outside its bounded range".into());
        }
        Ok(())
    }
}

/// Durable audit fact for one verdict, appended to the event log before any
/// approval bytes are typed (the `GuardrailRecord` precedent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationRecord {
    /// Pane whose prompt was evaluated.
    pub pane: PaneId,
    /// The waiting item evaluated. Carrying it here means decisions about
    /// distinct items are never adjacent duplicates, so the event log's
    /// duplicate suppression can never swallow a decision.
    pub waiting_id: u64,
    /// Foreground process-group identity the verdict applied to.
    pub invocation: Option<i32>,
    /// Provider id, recorded for audit only; the engine never branches on it.
    pub agent: String,
    /// Tool the prompt asked about.
    pub tool: String,
    /// Command preview the verdict was computed from.
    pub preview: String,
    /// The verdict reached before any side effect.
    pub verdict: DelegateVerdict,
}

/// Programs whose purpose is privilege escalation.
const DENY_PRIVILEGE: &[&str] = &["sudo", "doas", "su", "pkexec", "run0"];
/// Programs whose purpose crosses the machine boundary. Delegated approval
/// must never move Project data off the box or pull remote content in.
const DENY_NETWORK: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "lftp",
    "telnet", "mosh", "rclone", "aria2c", "http", "https", "xh",
];
/// Programs that mutate the host system rather than the Project.
const DENY_SYSTEM: &[&str] = &[
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "brew",
    "snap",
    "flatpak",
    "systemctl",
    "service",
    "launchctl",
];
/// Programs that destroy filesystem content.
const DENY_FILESYSTEM: &[&str] = &["rm", "shred", "srm", "unlink", "wipefs", "dd"];
/// Shells and command runners whose argv hides the real command from this
/// lexer. Allowing them would nullify the floor.
const DENY_SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh", "env", "eval"];
/// Interpreters denied only with inline-code flags: a script path inside the
/// Project is reviewable, while `-c` code is opaque to policy.
const INLINE_CODE_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "node", "deno", "bun", "php", "lua",
];
/// Git operations that destroy local work or publish it.
const DENY_GIT_SUBCOMMANDS: &[&str] = &[
    "push",
    "reset",
    "clean",
    "rebase",
    "checkout",
    "restore",
    "switch",
    "update-ref",
];
/// Git global flags that can redirect execution or repository identity.
/// `-c name=value` (and `--config-env`) can define an alias that launders a
/// denied program through an innocent subcommand name, and `-C`, `--git-dir`,
/// `--work-tree`, `--exec-path`, `--bare`, and `--namespace` point git at a
/// repository or helper other than the pane's own Project.
fn git_flag_redirects(word: &str) -> bool {
    word.starts_with("-c")
        || word.starts_with("-C")
        || word.starts_with("--git-dir")
        || word.starts_with("--work-tree")
        || word.starts_with("--exec-path")
        || word.starts_with("--config-env")
        || word.starts_with("--namespace")
        || word == "--bare"
}
/// Path components that hold repository internals or credential material.
const DENY_PATH_COMPONENTS: &[&str] = &[".git", ".ssh", ".aws", ".gnupg", ".docker", ".kube"];
/// Exact file names that hold credentials even outside a dotted directory.
const DENY_PATH_NAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".htpasswd",
];

/// Evaluate one permission prompt: deny wins, any uncertainty withholds.
///
/// The order is load-bearing and must not change: kind gate first, then the
/// shell-word lexer (substitution, redirection, pipes, and chaining refuse),
/// then the compiled-in deny floor, then the allowlist with Project-rooted
/// path containment, and finally the default withhold.
pub fn evaluate_delegation(policy: &DelegationPolicy, facts: &DelegationFacts) -> DelegateVerdict {
    if facts.kind != WaitingKind::Permission {
        return withhold("only permission prompts can be delegated");
    }
    if facts.tool.is_empty() || facts.preview.trim().is_empty() {
        return withhold("the prompt names no tool and command");
    }
    let Some(words) = lex_command(facts.preview).filter(|words| !words.is_empty()) else {
        return withhold("command syntax is outside the delegable subset");
    };
    if let Some(reason) = deny_floor_violation(&words, facts.project_root) {
        return withhold(reason);
    }
    if allowlist_allows(&policy.allow, &words) {
        DelegateVerdict::Allow
    } else {
        withhold("command is not on the delegation allowlist")
    }
}

fn withhold(reason: impl Into<String>) -> DelegateVerdict {
    DelegateVerdict::Withhold {
        reason: reason.into(),
    }
}

/// Split a command line into words with shell quoting rules, or refuse. The
/// delegable subset is a single simple command: any substitution (`$(`,
/// backtick, `${`), redirection, pipe, chaining (`;`, `&&`, `||`, `&`), or an
/// unterminated quote refuses the whole line, because the provider's shell
/// would evaluate those constructs opaquely to this lexer. Quoted operators
/// are literal text, exactly as a shell treats them.
fn lex_command(text: &str) -> Option<Vec<String>> {
    const MAX_WORDS: usize = 256;
    let mut words = Vec::new();
    let mut word = String::new();
    let mut chars = text.chars().peekable();
    let mut open = false;
    'outer: while let Some(character) = chars.next() {
        match character {
            '\'' => {
                open = true;
                for inner in chars.by_ref() {
                    if inner == '\'' {
                        continue 'outer;
                    }
                    word.push(inner);
                }
                // Unterminated single quote.
                return None;
            }
            '"' => {
                open = true;
                while let Some(inner) = chars.next() {
                    match inner {
                        '"' => continue 'outer,
                        '\\' => match chars.next() {
                            Some(escaped @ ('"' | '\\')) => word.push(escaped),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return None,
                        },
                        // Substitution is live inside double quotes.
                        '$' if matches!(chars.peek(), Some('(' | '{')) => return None,
                        '`' => return None,
                        _ => word.push(inner),
                    }
                }
                // Unterminated double quote.
                return None;
            }
            '\\' => match chars.next() {
                Some(escaped) => {
                    open = true;
                    word.push(escaped);
                }
                None => return None,
            },
            '$' if matches!(chars.peek(), Some('(' | '{')) => return None,
            '`' | ';' | '&' | '|' | '<' | '>' | '\n' | '\r' => return None,
            character if character.is_whitespace() => {
                if open {
                    words.push(std::mem::take(&mut word));
                    open = false;
                }
                if words.len() > MAX_WORDS {
                    return None;
                }
            }
            character => {
                open = true;
                word.push(character);
            }
        }
    }
    if open {
        words.push(word);
    }
    if words.len() > MAX_WORDS {
        return None;
    }
    Some(words)
}

/// The compiled-in deny floor: privilege escalation, network actors, system
/// mutation, destructive filesystem and git commands, opaque execution, and
/// any path that escapes `project_root` or names credential material.
fn deny_floor_violation(words: &[String], project_root: &str) -> Option<String> {
    let program = program_basename(&words[0]);
    if DENY_PRIVILEGE.contains(&program) {
        return Some("privilege escalation is never delegated".into());
    }
    if DENY_NETWORK.contains(&program) {
        return Some("network actors are never delegated".into());
    }
    if DENY_SYSTEM.contains(&program) {
        return Some("system mutation is never delegated".into());
    }
    if DENY_FILESYSTEM.contains(&program) || program.starts_with("mkfs") {
        return Some("destructive filesystem commands are never delegated".into());
    }
    if DENY_SHELLS.contains(&program) {
        return Some("opaque command execution is never delegated".into());
    }
    if INLINE_CODE_INTERPRETERS.contains(&program)
        && words[1..].iter().any(|word| word == "-c" || word == "-e")
    {
        return Some("inline interpreter code is never delegated".into());
    }
    if program == "git" {
        if let Some(reason) = git_floor_violation(&words[1..]) {
            return Some(reason);
        }
    }
    check_paths(words, project_root).err()
}

/// Git's destructive surface is subcommand- and flag-scoped, so one program
/// needs its own floor. The subcommand is the first non-flag word; global
/// flags before it refuse outright when they can redirect execution.
fn git_floor_violation(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let word = &args[index];
        if !word.starts_with('-') {
            break;
        }
        if git_flag_redirects(word) {
            return Some("git flags that redirect execution are never delegated".into());
        }
        index += 1;
    }
    let subcommand = args.get(index)?;
    if DENY_GIT_SUBCOMMANDS.contains(&subcommand.as_str()) {
        return Some("destructive git operations are never delegated".into());
    }
    let rest = &args[index + 1..];
    match subcommand.as_str() {
        "branch" | "tag"
            if rest
                .iter()
                .any(|word| matches!(word.as_str(), "-d" | "-D" | "--delete")) =>
        {
            Some("destructive git operations are never delegated".into())
        }
        "stash"
            if rest
                .iter()
                .any(|word| matches!(word.as_str(), "drop" | "pop" | "clear")) =>
        {
            Some("destructive git operations are never delegated".into())
        }
        _ => None,
    }
}

/// Every path-looking argument, including the program itself and `--flag=`
/// values, must normalize inside `project_root` and stay clear of credential
/// material. Containment is lexical: the root is canonical, and a symlink
/// inside the Project that points out is the provider's own sandbox question,
/// not something a pure evaluator can see.
fn check_paths(words: &[String], project_root: &str) -> Result<(), String> {
    for word in words {
        // Credential file names need no separator to name credential
        // material, so they are checked even as bare words.
        if is_credential_name(word) {
            return Err("credential and dotfile paths are never delegated".into());
        }
        if let Some((_, value)) = word.split_once('=') {
            if word.starts_with('-') && is_path_like(value) {
                check_one_path(value, project_root)?;
            }
            continue;
        }
        if is_path_like(word) {
            check_one_path(word, project_root)?;
        }
    }
    Ok(())
}

/// Exact names and suffixes that hold private keys or tokens.
fn is_credential_name(name: &str) -> bool {
    DENY_PATH_NAMES.contains(&name) || name.ends_with(".pem") || name.ends_with(".key")
}

/// A word is treated as a path when it carries a separator, a relative
/// anchor, or a dot prefix (`.env` and `.git` need no separator to name
/// credential material). Bare words (`test`, `--workspace`) are arguments,
/// not paths.
fn is_path_like(word: &str) -> bool {
    word.starts_with('/') || word.starts_with('~') || word.starts_with('.') || word.contains('/')
}

fn check_one_path(word: &str, project_root: &str) -> Result<(), String> {
    if word.starts_with('~') {
        return Err(format!(
            "home-relative path '{word}' cannot be verified inside the Project root"
        ));
    }
    let root = normalize_path(project_root);
    let candidate = if word.starts_with('/') {
        normalize_path(word)
    } else {
        let mut joined = root.clone();
        if normalize_into(&mut joined, word).is_err() {
            return Err(format!("path '{word}' escapes the Project root"));
        }
        joined
    };
    if !within_root(&root, &candidate) {
        return Err(format!("path '{word}' escapes the Project root"));
    }
    for component in &candidate[root.len()..] {
        if DENY_PATH_COMPONENTS.contains(&component.as_str()) || component.starts_with(".env") {
            return Err("credential and dotfile paths are never delegated".into());
        }
    }
    if let Some(name) = candidate.last() {
        if is_credential_name(name) {
            return Err("credential and dotfile paths are never delegated".into());
        }
    }
    Ok(())
}

/// Lexically normalize to absolute components: `.` and empty segments drop,
/// `..` pops, and a pop past the root is an escape.
fn normalize_path(path: &str) -> Vec<String> {
    let mut components = Vec::new();
    let _ = normalize_into(&mut components, path);
    components
}

fn normalize_into(components: &mut Vec<String>, path: &str) -> Result<(), ()> {
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(());
                }
            }
            segment => components.push(segment.to_string()),
        }
    }
    Ok(())
}

fn within_root(root: &[String], candidate: &[String]) -> bool {
    candidate.len() >= root.len() && candidate[..root.len()] == root[..]
}

/// The program identity used for deny decisions: a bare name matches exactly,
/// and an invoked path matches on its final component so `/usr/bin/sudo` is
/// the same actor as `sudo`.
fn program_basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// A rule allows the invocation when the program matches (exact, or by final
/// component for an invoked path) and the rule's argument words are a
/// word-boundary prefix of the invocation's arguments.
fn allowlist_allows(rules: &[CommandRule], words: &[String]) -> bool {
    rules.iter().any(|rule| {
        (rule.program == words[0] || rule.program == program_basename(&words[0]))
            && rule
                .prefix_words()
                .is_some_and(|prefix| words.len() > prefix.len() && words[1..].starts_with(&prefix))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(rules: &[&str]) -> DelegationPolicy {
        DelegationPolicy {
            allow: rules
                .iter()
                .map(|rule| CommandRule::parse(rule).unwrap())
                .collect(),
            max_answers_per_hour: 30,
        }
    }

    fn facts<'a>(tool: &'a str, preview: &'a str) -> DelegationFacts<'a> {
        DelegationFacts {
            kind: WaitingKind::Permission,
            tool,
            preview,
            project_root: "/work/api",
        }
    }

    fn allows(policy: &DelegationPolicy, facts: &DelegationFacts) -> bool {
        evaluate_delegation(policy, facts) == DelegateVerdict::Allow
    }

    fn withhold_reason(policy: &DelegationPolicy, facts: &DelegationFacts) -> String {
        match evaluate_delegation(policy, facts) {
            DelegateVerdict::Withhold { reason } => reason,
            verdict => panic!("expected withhold, got {verdict:?}"),
        }
    }

    #[test]
    fn anything_but_a_permission_prompt_withholds_by_construction() {
        for kind in [
            WaitingKind::Question,
            WaitingKind::Workflow,
            WaitingKind::Relay,
        ] {
            let mut facts = facts("Bash", "cargo test");
            facts.kind = kind;
            assert_eq!(
                withhold_reason(&rules(&["cargo test"]), &facts),
                "only permission prompts can be delegated"
            );
        }
    }

    #[test]
    fn a_prompt_without_a_structured_command_withholds() {
        assert_eq!(
            withhold_reason(&rules(&["cargo test"]), &facts("", "cargo test")),
            "the prompt names no tool and command"
        );
        assert_eq!(
            withhold_reason(&rules(&["cargo test"]), &facts("Bash", "   ")),
            "the prompt names no tool and command"
        );
    }

    #[test]
    fn allowlisted_commands_match_at_word_boundaries_only() {
        let policy = rules(&["cargo test", "git status", "ls"]);
        assert!(allows(&policy, &facts("Bash", "cargo test")));
        assert!(allows(&policy, &facts("Bash", "cargo test --workspace")));
        assert!(allows(&policy, &facts("Bash", "git status")));
        assert!(allows(&policy, &facts("Bash", "ls -la")));
        // A program rule with no argument prefix accepts any arguments.
        assert!(allows(&policy, &facts("Bash", "ls src/main.rs")));
        // The prefix is exact words: "test" never legitimizes "testnet" or publish.
        assert!(!allows(&policy, &facts("Bash", "cargo testnet")));
        assert!(!allows(&policy, &facts("Bash", "cargo publish")));
        assert!(!allows(&policy, &facts("Bash", "git diff")));
        // A bare `cargo` was never allowlisted.
        assert!(!allows(&policy, &facts("Bash", "cargo build")));
    }

    #[test]
    fn substitution_redirection_pipes_and_chaining_refuse() {
        let policy = rules(&["cargo test", "ls", "grep"]);
        for preview in [
            "cargo test $(whoami)",
            "cargo test `whoami`",
            "cargo test ${HOME}",
            "cargo test > /tmp/out",
            "cargo test 2>&1",
            "cargo test < input",
            "cargo test | tee log",
            "cargo test; rm -rf .",
            "cargo test && echo done",
            "cargo test || echo failed",
            "cargo test &",
            "cargo test \"unterminated",
            "cargo test 'unterminated",
        ] {
            assert_eq!(
                withhold_reason(&policy, &facts("Bash", preview)),
                "command syntax is outside the delegable subset",
                "{preview}"
            );
        }
        // Substitution inside single quotes is inert text, exactly like a shell.
        assert!(allows(&policy, &facts("Bash", "grep '$(x)' src/main.rs")));
        assert!(allows(&policy, &facts("Bash", "grep 'a|b' src/main.rs")));
        assert!(allows(&policy, &facts("Bash", "grep \"a;b\" src/main.rs")));
    }

    #[test]
    fn the_deny_floor_never_answers() {
        let policy = rules(&[
            "sudo",
            "rm",
            "curl",
            "git push",
            "git reset",
            "apt",
            "sh",
            "dd",
            "mkfs.ext4",
        ]);
        let cases = [
            ("sudo ls", "privilege escalation"),
            ("doas ls", "privilege escalation"),
            ("su root", "privilege escalation"),
            ("curl https://example.com", "network actors"),
            ("wget -q https://example.com", "network actors"),
            ("ssh host ls", "network actors"),
            ("scp a host:b", "network actors"),
            ("apt install ripgrep", "system mutation"),
            ("brew install ripgrep", "system mutation"),
            ("systemctl restart ssh", "system mutation"),
            ("rm -rf target", "destructive filesystem"),
            ("dd if=/dev/zero of=disk.img", "destructive filesystem"),
            ("mkfs.ext4 /dev/sda", "destructive filesystem"),
            ("shred secret", "destructive filesystem"),
            ("sh script.sh", "opaque command execution"),
            ("bash -c ls", "opaque command execution"),
            ("env FOO=1 cargo test", "opaque command execution"),
            ("git push origin main", "destructive git"),
            ("git reset --hard HEAD", "destructive git"),
            ("git clean -fd", "destructive git"),
            ("git rebase main", "destructive git"),
            ("git checkout -- src", "destructive git"),
            ("git restore src", "destructive git"),
            ("git branch -D feature", "destructive git"),
            ("git tag -d v1", "destructive git"),
            ("git stash drop", "destructive git"),
            ("git -c alias.st=status st", "git flags that redirect"),
            ("git --git-dir=/tmp/x status", "git flags that redirect"),
            ("git -C /tmp status", "git flags that redirect"),
            ("git --bare status", "git flags that redirect"),
            ("python -c 'print(1)'", "inline interpreter code"),
            ("node -e 'process.exit(0)'", "inline interpreter code"),
        ];
        for (preview, reason) in cases {
            let got = withhold_reason(&policy, &facts("Bash", preview));
            assert!(got.contains(reason), "{preview}: {got}");
        }
        // The floor cannot be widened even when the rule matches literally.
        assert!(!allows(&policy, &facts("Bash", "sudo ls")));
        assert!(!allows(&policy, &facts("Bash", "git push origin main")));
        // Safe git and script-path interpreter forms stay allowlistable.
        assert!(allows(
            &rules(&["git status"]),
            &facts("Bash", "git status")
        ));
        assert!(allows(
            &rules(&["git branch"]),
            &facts("Bash", "git branch")
        ));
        assert!(allows(
            &rules(&["python manage.py"]),
            &facts("Bash", "python manage.py test")
        ));
    }

    #[test]
    fn paths_must_stay_inside_the_project_root() {
        let policy = rules(&["cargo test", "cat", "ls", "./tool"]);
        // Absolute and relative escapes refuse, through plain and dotted paths.
        for preview in [
            "cat /etc/passwd",
            "cat ../secret",
            "cat src/../../../etc/passwd",
            "cat ~/id_rsa",
            "cat sub/../../escape",
            "cat --file=/etc/passwd",
            "ls /tmp",
        ] {
            assert!(!allows(&policy, &facts("Bash", preview)), "{preview}");
        }
        let escape = withhold_reason(&policy, &facts("Bash", "cat ../secret"));
        assert!(escape.contains("escapes the Project root"), "{escape}");
        let home = withhold_reason(&policy, &facts("Bash", "cat ~/id_rsa"));
        assert!(home.contains("cannot be verified"), "{home}");
        // Paths inside the root allow, normalized through dots and subdirs.
        assert!(allows(&policy, &facts("Bash", "cat src/main.rs")));
        assert!(allows(&policy, &facts("Bash", "cat ./src/main.rs")));
        assert!(allows(&policy, &facts("Bash", "cat src/../README.md")));
        assert!(allows(&policy, &facts("Bash", "cat /work/api/src/main.rs")));
        assert!(allows(&policy, &facts("Bash", "cat --file=src/main.rs")));
        assert!(allows(
            &policy,
            &facts("Bash", "cargo test --manifest-path Cargo.toml")
        ));
        // A project-local program path is itself containment-checked.
        assert!(allows(&policy, &facts("Bash", "./tool run")));
        assert!(!allows(
            &rules(&["/tmp/tool"]),
            &facts("Bash", "/tmp/tool run")
        ));
    }

    #[test]
    fn credential_and_dotfile_paths_are_never_delegated() {
        let policy = rules(&["cat", "ls"]);
        for preview in [
            "cat .env",
            "cat .env.local",
            "cat config/.envrc",
            "cat .ssh/id_rsa",
            "cat .aws/credentials",
            "cat .git/config",
            "cat src/.git/hooks/x",
            "cat .netrc",
            "cat keys/server.pem",
            "cat keys/private.key",
            "cat id_ed25519",
            "cat .gnupg/secring.gpg",
        ] {
            assert!(!allows(&policy, &facts("Bash", preview)), "{preview}");
        }
        // Dotted names that are not credential material stay allowlistable.
        assert!(allows(&policy, &facts("Bash", "ls .github/workflows")));
        assert!(allows(&policy, &facts("Bash", "cat .gitignore")));
    }

    #[test]
    fn lexer_produces_shell_words_and_bounds_input() {
        assert_eq!(
            lex_command("cargo test --workspace").unwrap(),
            vec!["cargo", "test", "--workspace"]
        );
        assert_eq!(
            lex_command("grep 'two words' \"and \\\"quoted\\\"\"").unwrap(),
            vec!["grep", "two words", "and \"quoted\""]
        );
        assert_eq!(lex_command("one\\ two").unwrap(), vec!["one two"]);
        assert!(lex_command("   ").unwrap().is_empty());
        assert!(lex_command(&"word ".repeat(300)).is_none());
    }

    #[test]
    fn rules_parse_bounds_and_reject_operators() {
        assert_eq!(
            CommandRule::parse("cargo test").unwrap(),
            CommandRule {
                program: "cargo".into(),
                arg_prefix: Some("test".into()),
            }
        );
        assert_eq!(
            CommandRule::parse("ls").unwrap(),
            CommandRule {
                program: "ls".into(),
                arg_prefix: None,
            }
        );
        for bad in ["", "cargo; rm", "cargo $(x)", "cargo | tee", "cargo \"open"] {
            assert!(CommandRule::parse(bad).is_err(), "{bad}");
        }
        assert!(CommandRule::parse(&"x".repeat(300)).is_err());
        assert!(CommandRule::parse("cargo test\t--workspace").is_ok());
    }

    #[test]
    fn policy_validation_enforces_bounds() {
        let mut policy = DelegationPolicy::default();
        assert!(policy.validate().is_ok());
        policy.max_answers_per_hour = 0;
        assert!(policy.validate().is_err());
        policy.max_answers_per_hour = DELEGATION_MAX_ANSWERS_PER_HOUR + 1;
        assert!(policy.validate().is_err());
        policy.max_answers_per_hour = 1;
        policy.allow = (0..=DELEGATION_MAX_RULES)
            .map(|index| CommandRule {
                program: format!("program-{index}"),
                arg_prefix: None,
            })
            .collect();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn records_carry_the_waiting_id_so_decisions_cannot_be_suppressed() {
        // Two verdicts about distinct waiting items are never equal, so the
        // event log's adjacent-duplicate suppression can never swallow one.
        let record = DelegationRecord {
            pane: PaneId(7),
            waiting_id: 42,
            invocation: Some(100),
            agent: "claude".into(),
            tool: "Bash".into(),
            preview: "cargo test".into(),
            verdict: DelegateVerdict::Allow,
        };
        let next = DelegationRecord {
            waiting_id: 43,
            ..record.clone()
        };
        assert_ne!(record, next);
    }
}
