use std::collections::BTreeSet;

use chrono::{DateTime, Timelike, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::config::AnomalyDetectionConfig;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyAlert {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub code: &'static str,
    pub message: String,
    pub grant_id: uuid::Uuid,
    pub count: usize,
}

pub fn detect_grant_anomalies(
    config: &AnomalyDetectionConfig,
    events: &[Value],
    grant_id: uuid::Uuid,
    now: DateTime<Utc>,
) -> Vec<AnomalyAlert> {
    if !config.enabled {
        return Vec::new();
    }

    let samples = execution_samples(events, grant_id);
    let mut alerts = Vec::new();
    let recent_count = samples
        .iter()
        .filter(|sample| now.signed_duration_since(sample.timestamp).num_minutes() <= 60)
        .count();
    if recent_count > config.max_runs_per_hour_per_grant {
        alerts.push(AnomalyAlert {
            event_type: "anomaly.grant_frequency",
            code: "anomaly.grant_frequency",
            message: format!("grant used {recent_count} times in the last hour"),
            grant_id,
            count: recent_count,
        });
    }

    let hour = now.hour() as u8;
    if outside_working_hours(hour, config.working_hours_start, config.working_hours_end) {
        alerts.push(AnomalyAlert {
            event_type: "anomaly.outside_hours",
            code: "anomaly.outside_hours",
            message: format!("grant used outside configured working hours at {hour:02}:00"),
            grant_id,
            count: 1,
        });
    }

    let branches = samples
        .iter()
        .filter_map(|sample| sample.branch.as_deref())
        .collect::<BTreeSet<_>>();
    if branches.len() > config.max_branches_per_grant {
        alerts.push(AnomalyAlert {
            event_type: "anomaly.grant_branch_spread",
            code: "anomaly.grant_branch_spread",
            message: format!("grant used across {} branches", branches.len()),
            grant_id,
            count: branches.len(),
        });
    }

    alerts
}

fn execution_samples(events: &[Value], grant_id: uuid::Uuid) -> Vec<ExecutionSample> {
    events
        .iter()
        .filter_map(|event| {
            let timestamp = event
                .get("timestamp")
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc))?;
            let payload = event.get("payload")?;
            if payload.get("type").and_then(Value::as_str) != Some("execution.finished") {
                return None;
            }
            let event_grant_id = payload
                .get("grantId")
                .and_then(Value::as_str)
                .and_then(|value| uuid::Uuid::parse_str(value).ok())?;
            if event_grant_id != grant_id {
                return None;
            }
            Some(ExecutionSample {
                timestamp,
                branch: payload
                    .get("branch")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect()
}

fn outside_working_hours(hour: u8, start: u8, end: u8) -> bool {
    if start == end {
        return false;
    }
    if start < end {
        hour < start || hour >= end
    } else {
        hour < start && hour >= end
    }
}

#[derive(Debug)]
struct ExecutionSample {
    timestamp: DateTime<Utc>,
    branch: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn config() -> AnomalyDetectionConfig {
        AnomalyDetectionConfig {
            enabled: true,
            working_hours_start: 8,
            working_hours_end: 20,
            max_runs_per_hour_per_grant: 2,
            max_branches_per_grant: 2,
        }
    }

    fn event(grant_id: uuid::Uuid, branch: &str, timestamp: DateTime<Utc>) -> Value {
        json!({
            "timestamp": timestamp.to_rfc3339(),
            "payload": {
                "type": "execution.finished",
                "grantId": grant_id,
                "branch": branch
            }
        })
    }

    #[test]
    fn detects_frequency_hours_and_branch_spread() {
        let grant_id = uuid::Uuid::new_v4();
        let now = Utc.with_ymd_and_hms(2026, 5, 26, 21, 0, 0).unwrap();
        let events = vec![
            event(grant_id, "a", now),
            event(grant_id, "b", now),
            event(grant_id, "c", now),
        ];

        let alerts = detect_grant_anomalies(&config(), &events, grant_id, now);

        assert!(alerts
            .iter()
            .any(|alert| alert.code == "anomaly.grant_frequency"));
        assert!(alerts
            .iter()
            .any(|alert| alert.code == "anomaly.outside_hours"));
        assert!(alerts
            .iter()
            .any(|alert| alert.code == "anomaly.grant_branch_spread"));
    }

    #[test]
    fn ignores_disabled_clean_other_and_malformed_events() {
        let grant_id = uuid::Uuid::new_v4();
        let other_id = uuid::Uuid::new_v4();
        let now = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        let events = vec![
            event(other_id, "a", now),
            json!({ "timestamp": now.to_rfc3339(), "payload": { "type": "execution.started" }}),
            json!({ "timestamp": "bad", "payload": {} }),
        ];

        assert!(detect_grant_anomalies(&config(), &events, grant_id, now).is_empty());
        let disabled = AnomalyDetectionConfig {
            enabled: false,
            ..config()
        };
        assert!(detect_grant_anomalies(&disabled, &events, grant_id, now).is_empty());
    }

    #[test]
    fn handles_overnight_working_hours() {
        assert!(!outside_working_hours(23, 20, 8));
        assert!(!outside_working_hours(7, 20, 8));
        assert!(outside_working_hours(12, 20, 8));
        assert!(!outside_working_hours(12, 12, 12));
    }
}
