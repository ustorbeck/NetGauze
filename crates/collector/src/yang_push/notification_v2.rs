// Copyright (C) 2025-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// THIS IS NOT WORKING
// serde(flatten) cannot be used multiple times in the same struct if
// we have serde_json::Value as a field (too generic, everything will also
// match there)

use crate::telemetry::SubscriptionId;
/// References:
/// - https://datatracker.ietf.org/doc/html/rfc8639
/// - https://datatracker.ietf.org/doc/html/rfc8641
/// - https://datatracker.ietf.org/doc/html/draft-ietf-netconf-yang-notifications-versioning-08
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Notification {
    #[serde(rename = "eventTime")]
    event_time: String,

    #[serde(rename = "ietf-notification-sequencing:sysName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,

    #[serde(flatten)]
    notification: NotificationVariant,

    #[serde(flatten)]
    extra_fields: Value,
}

impl Notification {
    pub fn event_time(&self) -> &str {
        &self.event_time
    }
    pub fn node_id(&self) -> Option<&String> {
        self.node_id.as_ref()
    }
    pub fn notification(&self) -> &NotificationVariant {
        &self.notification
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum NotificationVariant {
    #[serde(rename = "ietf-subscribed-notifications:subscription-started")]
    SubscriptionStarted(SubscriptionStartedModified),

    #[serde(rename = "ietf-subscribed-notifications:subscription-modified")]
    SubscriptionModified(SubscriptionStartedModified),

    #[serde(rename = "ietf-subscribed-notifications:subscription-terminated")]
    SubscriptionTerminated(SubscriptionTerminated),

    #[serde(rename = "ietf-yang-push:push-update")]
    YangPushUpdate(YangPushUpdate),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SubscriptionStartedModified {
    id: SubscriptionId,

    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<String>,

    #[serde(flatten)]
    target: Target,

    // TODO: issue here, this is capturing fields that are also capture in Target
    // (probably due to Target being not specific with untagged...)
    #[serde(flatten)]
    extra_fields: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SubscriptionTerminated {
    id: SubscriptionId,

    reason: String,

    #[serde(flatten)]
    extra_fields: Value,
}

// +--ro (target)
// |  +--:(stream)
// |     +--ro (stream-filter)?
// |     |  +--:(by-reference)
// |     |  |  +--ro stream-filter-name
// |     |  |          stream-filter-ref
// |     |  +--:(within-subscription)
// |     |     +--ro (filter-spec)?
// |     |        +--:(stream-subtree-filter)
// |     |        |  +--ro stream-subtree-filter?   <anydata>
// |     |        |          {subtree}?
// |     |        +--:(stream-xpath-filter)
// |     |           +--ro stream-xpath-filter?     yang:xpath1.0
// |     |                   {xpath}?
// |     +--ro stream                               stream-ref
// |     +--ro replay-start-time?
// |     |       yang:date-and-time {replay}?
// |     +--ro replay-previous-event-time?
// |             yang:date-and-time {replay}?
// |  |  ...
// |  |  +--:(yp:datastore)
// |  |     +--ro yp:datastore                   identityref
// |  |     +--ro (yp:selection-filter)?
// |  |        +--:(yp:by-reference)
// |  |        |  +--ro yp:selection-filter-ref
// |  |        |          selection-filter-ref
// |  |        +--:(yp:within-subscription)
// |  |           +--ro (yp:filter-spec)?
// |  |              +--:(yp:datastore-subtree-filter)
// |  |              |  +--ro yp:datastore-subtree-filter?
// |  |              |          <anydata> {sn:subtree}?
// |  |              +--:(yp:datastore-xpath-filter)
// |  |                 +--ro yp:datastore-xpath-filter?
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Target {
    Stream {
        #[serde(rename = "stream-filter")]
        #[serde(flatten)]
        stream_filter: Option<StreamFilter>,

        #[serde(rename = "stream")]
        stream: String,

        #[serde(rename = "replay-start-time")]
        #[serde(skip_serializing_if = "Option::is_none")]
        replay_start_time: Option<chrono::DateTime<chrono::Utc>>,

        #[serde(rename = "replay-previous-event-time")]
        #[serde(skip_serializing_if = "Option::is_none")]
        replay_previous_event_time: Option<chrono::DateTime<chrono::Utc>>,
    },
    Datastore {
        #[serde(rename = "ietf-yang-push:datastore")]
        datastore: String,

        #[serde(rename = "ietf-yang-push:selection-filter")]
        #[serde(flatten)]
        selection_filter: Option<SelectionFilter>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum StreamFilter {
    ByReference {
        #[serde(rename = "stream-filter-name")]
        stream_filter_name: String,
    },
    WithinSubscription {
        #[serde(flatten)]
        filter_spec: Option<StreamFilterSpec>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum StreamFilterSpec {
    StreamSubtreeFilter {
        #[serde(rename = "stream-subtree-filter")]
        #[serde(skip_serializing_if = "Option::is_none")]
        stream_subtree_filter: Option<Value>,
    },
    StreamXpathFilter {
        #[serde(rename = "stream-xpath-filter")]
        #[serde(skip_serializing_if = "Option::is_none")]
        stream_xpath_filter: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SelectionFilter {
    ByReference {
        #[serde(rename = "ietf-yang-push:selection-filter-ref")]
        selection_filter_ref: String,
    },
    WithinSubscription {
        #[serde(flatten)]
        #[serde(rename = "ietf-yang-push:filter-spec")]
        filter_spec: Option<SelectionFilterSpec>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SelectionFilterSpec {
    DatastoreXpathFilter {
        #[serde(rename = "ietf-yang-push:datastore-xpath-filter")]
        #[serde(skip_serializing_if = "Option::is_none")]
        datastore_xpath_filter: Option<String>,
    },
    DatastoreSubtreeFilter {
        #[serde(rename = "ietf-yang-push:datastore-subtree-filter")]
        #[serde(skip_serializing_if = "Option::is_none")]
        datastore_subtree_filter: Option<Value>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct YangPushUpdate {
    id: SubscriptionId,

    #[serde(rename = "datastore-contents")]
    datastore_contents: Value,

    #[serde(flatten)]
    extra_fields: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::*;
    use serde_json;

    #[test]
    #[ignore] // This test is currently failing...
    fn test_sub_started_serialization() {
        // Create a SubscriptionStartedModified instance
        let sub_started = SubscriptionStartedModified {
            id: 1,
            encoding: Some("encode-json".to_string()),
            transport: Some("ietf-udp-notif-transport:udp-notif".to_string()),
            target: Target::Datastore {
                datastore: "ietf-datastores:running".to_string(),
                selection_filter: Some(SelectionFilter::WithinSubscription {
                    filter_spec: Some(SelectionFilterSpec::DatastoreXpathFilter {
                        datastore_xpath_filter: Some("test xpath filter".to_string()),
                    }),
                }),
            },
            extra_fields: serde_json::json!({}),
        };

        // Create a Notification instance
        let notification = Notification {
            event_time: "2025-04-25T12:00:00Z".to_string(),
            node_id: Some("example-node".to_string()),
            notification: NotificationVariant::SubscriptionStarted(sub_started),
            extra_fields: serde_json::json!({}),
        };

        // Serialize the Notification to JSON
        let serialized = serde_json::to_string(&notification).expect("Serialization failed");

        // Print the serialized JSON
        println!("{}", format!("Serialized JSON: {serialized}").yellow());

        // Deserialize the JSON back to a Notification
        let deserialized: Notification =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        // Serialize again to check if it matches the previous serialization
        let re_serialized = serde_json::to_string(&deserialized).expect("Re-serialization failed");
        println!("{}", format!("Re-serialized JSON: {re_serialized}").green());

        // Assert that the deserialized Notification matches the original
        assert_eq!(notification, deserialized);
    }
}
