use super::{Manifest, Rule, RuleAnchor, RuleRegion};
use uniterm_core::AgentStatus;

/// Grok Build resumes a session by id with `grok --resume <id>`.
pub const RESUME: &[&str] = &["grok", "--resume"];

// Priorities: visible blocked prompts beat activity titles (120 to 115);
// activity titles beat grid activity (110 to 100). Activity is anchored to a spinner or a
// line start so typed prompt text cannot impersonate it (75 to 60), and idle
// hints are the weakest positive signal (20 to 10). No rule matching means
// idle: the matcher never treats output volume as evidence.
pub const MANIFEST: Manifest = Manifest {
    id: "grok",
    executables: &["grok", "agent"],
    rules: &[
        Rule {
            status: AgentStatus::Permission,
            patterns: &["action required"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Title,
            priority: 125,
        },
        Rule {
            status: AgentStatus::Working,
            patterns: &[""],
            anchor: RuleAnchor::AnimatedTitle,
            region: RuleRegion::Title,
            priority: 105,
        },
        Rule {
            status: AgentStatus::Permission,
            patterns: &[
                "approval required",
                "allow this command",
                "confirm execution",
                "ctrl+o:yolo",
                "←/→:scope",
            ],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 120,
        },
        Rule {
            status: AgentStatus::Question,
            patterns: &[
                "waiting for your response",
                "select an option",
                "shift+x:dismiss",
            ],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 115,
        },
        Rule {
            status: AgentStatus::Error,
            patterns: &["grok api error", "rate limit", "request failed"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 80,
        },
        Rule {
            status: AgentStatus::Working,
            patterns: &["[stop]"],
            anchor: RuleAnchor::SpinnerSuffix,
            region: RuleRegion::Bottom,
            priority: 110,
        },
        Rule {
            status: AgentStatus::Working,
            patterns: &["thinking", "running tool", "generating"],
            anchor: RuleAnchor::SpinnerLine,
            region: RuleRegion::Bottom,
            priority: 75,
        },
        Rule {
            status: AgentStatus::Idle,
            patterns: &["ask grok", "type a message"],
            anchor: RuleAnchor::Anywhere,
            region: RuleRegion::Bottom,
            priority: 20,
        },
    ],
};

/// Interactive CLI arguments, kept beside this provider's detection rules.
pub(super) const LAUNCH: super::LaunchSpec = super::LaunchSpec {
    prefix: &[],
    prompt_flag: None,
    model_flag: Some("--model"),
    profile_flag: Some("--agent"),
};
