use super::{Manifest, Rule, RuleAnchor, RuleRegion};
use uniterm_core::AgentStatus;

/// Cursor Agent resumes a chat by id with `cursor-agent --resume <id>`.
pub const RESUME: &[&str] = &["cursor-agent", "--resume"];

// Priorities: visible blocked prompts beat activity titles (120 to 115);
// activity titles beat grid activity (110 to 100). Activity is anchored to a spinner or a
// line start so typed prompt text cannot impersonate it (75 to 60), and idle
// hints are the weakest positive signal (20 to 10). No rule matching means
// idle: the matcher never treats output volume as evidence.
pub const MANIFEST: Manifest = Manifest {
    id: "cursor",
    executables: &["agent", "cursor-agent"],
    rules: &[
        Rule {
            status: AgentStatus::Working,
            patterns: &[""],
            anchor: RuleAnchor::SpinnerLine,
            region: RuleRegion::Title,
            priority: 105,
        },
        Rule {
            status: AgentStatus::Permission,
            patterns: &[
                "approval required",
                "approve this command",
                "allow this command",
                "ask every time",
                "run everything",
                "run (once) (y)",
                "skip (esc or n)",
                "write to this file?",
                "reject & propose changes",
            ],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 120,
        },
        Rule {
            status: AgentStatus::Question,
            patterns: &["answer the question", "select an option", "enter to select"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 115,
        },
        Rule {
            status: AgentStatus::Error,
            patterns: &[
                "not authenticated",
                "authentication failed",
                "usage limit",
                "rate limit",
                "request failed",
            ],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 80,
        },
        Rule {
            status: AgentStatus::Working,
            patterns: &[""],
            anchor: RuleAnchor::SpinnerLine,
            region: RuleRegion::Bottom,
            priority: 75,
        },
        Rule {
            status: AgentStatus::Working,
            patterns: &["ctrl+c to stop"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 60,
        },
        Rule {
            status: AgentStatus::Idle,
            patterns: &["plan, search, build anything", "add a follow-up"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 20,
        },
        Rule {
            status: AgentStatus::Idle,
            patterns: &["cursor agent"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 10,
        },
    ],
};

/// Interactive CLI arguments, kept beside this provider's detection rules.
/// What a human types to approve this provider's permission prompt once.
/// Cursor Agent's prompt offers "run (once) (y)", so the delegated reply is
/// `y` followed by the usual Enter. Kept beside the detection rules so
/// nothing outside this module branches on the agent id.
pub(super) const APPROVAL_REPLY: &str = "y";

/// What a human types to approve this provider's permission prompt and stop
/// it from asking again. Cursor Agent's prompt offers an "always allow"
/// key, so the delegated always-reply is `a` followed by the usual Enter. A
/// prompt variant that does not accept it re-surfaces and gets the plain
/// yes-reply from then on.
pub(super) const ALWAYS_REPLY: &str = "a";

/// Cursor Agent's complete permission dialog: the approval header, the
/// key-labeled options, and the skip footer all visible at once. A screen
/// showing only part of that triple is still rendering and must never be
/// answered early.
pub(super) const DIALOG_SIGNATURE: super::DialogSignature = super::DialogSignature {
    question: &[
        "approval required",
        "approve this command",
        "allow this command",
        "write to this file?",
    ],
    options: &["run (once) (y)"],
    footer: &["skip (esc or n)"],
};

pub(super) const LAUNCH: super::LaunchSpec = super::LaunchSpec {
    prefix: &[],
    prompt_flag: None,
    model_flag: Some("--model"),
    profile_flag: None,
};
