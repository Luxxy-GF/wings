use crate::state::Snapshot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RemoteMsg {
    Snapshot { snapshot: Snapshot },
    MetricsRequest { req_id: u64 },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum NodeMsg {
    Metrics {
        req_id: u64,
        body: serde_json::Value,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // RemoteMsg

    #[test]
    fn panel_msg_snapshot_round_trips_under_its_tag() {
        let msg = RemoteMsg::Snapshot {
            snapshot: Snapshot {
                epoch: 7,
                jwt_pubkey: crate::hash::Hash32([1; 32]),
                nodes: vec![],
                servers: vec![],
                acls: vec![],
            },
        };
        let text = serde_json::to_string(&msg).unwrap();
        assert!(text.starts_with(r#"{"t":"snapshot","snapshot":{"epoch":7"#));

        let back = serde_json::from_str::<RemoteMsg>(&text).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
    }

    #[test]
    fn panel_msg_metrics_request_round_trips_under_its_tag() {
        let text = serde_json::to_string(&RemoteMsg::MetricsRequest { req_id: 3 }).unwrap();
        assert_eq!(text, r#"{"t":"metrics_request","req_id":3}"#);

        let back = serde_json::from_str::<RemoteMsg>(&text).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
    }

    #[test]
    fn panel_msg_rejects_an_unknown_tag_rather_than_ignoring_it() {
        assert!(serde_json::from_str::<RemoteMsg>(r#"{"t":"reboot"}"#).is_err());
    }

    // NodeMsg

    #[test]
    fn node_msg_metrics_round_trips_under_its_tag() {
        let reply = NodeMsg::Metrics {
            req_id: 3,
            body: serde_json::json!({ "peers": [] }),
        };
        let text = serde_json::to_string(&reply).unwrap();
        assert_eq!(text, r#"{"t":"metrics","req_id":3,"body":{"peers":[]}}"#);

        let back = serde_json::from_str::<NodeMsg>(&text).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
    }
}
