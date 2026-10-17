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
//! I/O, no async, no provider ids. The human's arm is the consent, so an armed
//! Pane approves every permission prompt, structured or screen-detected; the
//! kind gate below is the whole verdict policy - design and planning questions
//! are the human's own call by construction.

use serde::{Deserialize, Serialize};

use crate::{PaneId, WaitingKind};

/// Hard bound on the hourly auto-answer budget.
pub const DELEGATION_MAX_ANSWERS_PER_HOUR: u16 = 240;
/// Default hourly budget when the Workspace config does not set one.
pub const DELEGATION_DEFAULT_ANSWERS_PER_HOUR: u16 = 30;

/// Workspace delegation policy after config parsing: the hourly auto-answer
/// budget an armed Pane may spend before delegation disarms itself and
/// hands every prompt back to the human. The budget is the product's
/// standing blast-radius bound on an arm; the kind gate below decides each
/// individual verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationPolicy {
    /// Maximum auto-answers per armed Pane per hour before delegation
    /// disarms itself until the human re-arms.
    pub max_answers_per_hour: u16,
}

impl Default for DelegationPolicy {
    fn default() -> Self {
        Self {
            max_answers_per_hour: DELEGATION_DEFAULT_ANSWERS_PER_HOUR,
        }
    }
}

impl DelegationPolicy {
    /// Reject impossible durable values rather than silently changing an
    /// armed Pane's contract.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=DELEGATION_MAX_ANSWERS_PER_HOUR).contains(&self.max_answers_per_hour) {
            return Err("max answers per hour is outside its bounded range".into());
        }
        Ok(())
    }
}

/// Pure outcome. There is deliberately no `Deny` verdict that types anything:
/// the supervisor only ever types an approval, and only on `Allow`.
/// `Withhold` leaves the waiting item untouched for the human and says why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegateVerdict {
    /// The prompt is a permission prompt, which an armed Pane answers.
    Allow,
    /// The prompt stays with the human; the reason is auditable.
    Withhold {
        /// Human-readable explanation, recorded in the event log.
        reason: String,
    },
}

/// The serde shape of a verdict. serde's internally-tagged enum form needs
/// `deserialize_any`, which bincode (the attach protocol) does not implement,
/// so a derived tagged enum silently fails to decode on that transport while
/// working everywhere JSON carries it. This plain struct keeps the `outcome`
/// tag in the JSON event log and decodes on every transport; `reason`
/// defaults so event streams written before it existed still replay.
#[derive(Serialize, Deserialize)]
struct VerdictSerde {
    outcome: String,
    #[serde(default)]
    reason: Option<String>,
}

impl Serialize for DelegateVerdict {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            DelegateVerdict::Allow => VerdictSerde {
                outcome: "allow".into(),
                reason: None,
            },
            DelegateVerdict::Withhold { reason } => VerdictSerde {
                outcome: "withhold".into(),
                reason: Some(reason.clone()),
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DelegateVerdict {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = VerdictSerde::deserialize(deserializer)?;
        match wire.outcome.as_str() {
            "allow" => Ok(DelegateVerdict::Allow),
            "withhold" => Ok(DelegateVerdict::Withhold {
                reason: wire.reason.unwrap_or_default(),
            }),
            other => Err(serde::de::Error::custom(format!(
                "unknown delegation verdict '{other}'"
            ))),
        }
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
    /// Command preview the verdict was recorded against.
    pub preview: String,
    /// The verdict reached before any side effect.
    pub verdict: DelegateVerdict,
}

/// Evaluate one waiting item for an armed Pane: a permission prompt allows,
/// everything else withholds. Design and planning questions are the human's
/// own call by construction, which is the entire verdict policy; the server
/// layers invocation scoping, the budget, and the loop guard on top.
pub fn evaluate_delegation(kind: WaitingKind) -> DelegateVerdict {
    if kind != WaitingKind::Permission {
        return DelegateVerdict::Withhold {
            reason: "only permission prompts can be delegated".into(),
        };
    }
    DelegateVerdict::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_prompts_allow() {
        assert_eq!(
            evaluate_delegation(WaitingKind::Permission),
            DelegateVerdict::Allow
        );
    }

    #[test]
    fn anything_but_a_permission_prompt_withholds_by_construction() {
        for kind in [
            WaitingKind::Question,
            WaitingKind::Workflow,
            WaitingKind::Relay,
        ] {
            assert_eq!(
                evaluate_delegation(kind),
                DelegateVerdict::Withhold {
                    reason: "only permission prompts can be delegated".into(),
                },
                "{kind:?}"
            );
        }
    }

    #[test]
    fn verdict_serialization_keeps_the_outcome_tag_and_replays_legacy_streams() {
        // The audit contract is the `outcome` tag; bincode (the attach
        // protocol) cannot decode serde's internally-tagged enums, so this
        // shape comes from the plain VerdictSerde struct, not a derive.
        assert_eq!(
            serde_json::to_value(DelegateVerdict::Allow).unwrap(),
            serde_json::json!({ "outcome": "allow", "reason": null })
        );
        assert_eq!(
            serde_json::to_value(DelegateVerdict::Withhold {
                reason: "the identical prompt was re-asked".into(),
            })
            .unwrap(),
            serde_json::json!({ "outcome": "withhold", "reason": "the identical prompt was re-asked" })
        );
        // Streams written before `reason` existed still replay.
        assert_eq!(
            serde_json::from_str::<DelegateVerdict>(r#"{"outcome":"allow"}"#).unwrap(),
            DelegateVerdict::Allow
        );
        assert_eq!(
            serde_json::from_str::<DelegateVerdict>(r#"{"outcome":"withhold","reason":"x"}"#)
                .unwrap(),
            DelegateVerdict::Withhold { reason: "x".into() }
        );
        assert!(serde_json::from_str::<DelegateVerdict>(r#"{"outcome":"deny"}"#).is_err());
    }

    #[test]
    fn policy_validation_enforces_the_budget_bound() {
        assert!(DelegationPolicy::default().validate().is_ok());
        for max_answers_per_hour in [0, DELEGATION_MAX_ANSWERS_PER_HOUR + 1] {
            assert!(
                DelegationPolicy {
                    max_answers_per_hour
                }
                .validate()
                .is_err(),
                "{max_answers_per_hour}"
            );
        }
        assert!(DelegationPolicy {
            max_answers_per_hour: 1
        }
        .validate()
        .is_ok());
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
