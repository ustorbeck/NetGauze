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

// TODO: documentation here..
/// Ref: https://datatracker.ietf.org/doc/html/draft-netana-nmop-message-broker-telemetry-message-00
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

pub type SubscriptionId = u32;

/// Telemetry Message
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename = "ietf-telemetry-message:notification")]
#[serde(rename_all = "kebab-case")]
pub struct TelemetryMessage {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub notification_protocol: NotificationProtocol,
    pub notification_encoding: NotificationEncoding,
    pub notification_transport: NotificationTransport,
    pub network_node_manifest: Manifest,
    pub data_collection_manifest: Manifest,
    pub telemetry_notification_metadata: NotificationMetadata,
    pub data_collection_metadata: DataCollectionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

/// Notification protocol used to deliver the notification to the data
/// collection.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub enum NotificationProtocol {
    #[serde(rename = "netconf")]
    Netconf,

    #[serde(rename = "restconf")]
    Restconf,

    #[serde(rename = "yp-configured")]
    YangPushConfigured,

    #[serde(rename = "yp-dynamic")]
    YangPushDynamic,

    #[default]
    Unknown,
}

impl NotificationProtocol {
    pub fn from_string(protocol_str: &str) -> Self {
        match protocol_str {
            "netconf" => NotificationProtocol::Netconf,
            "restconf" => NotificationProtocol::Restconf,
            "yang-push-configured" => NotificationProtocol::YangPushConfigured,
            "yang-push-dynamic" => NotificationProtocol::YangPushDynamic,
            _ => NotificationProtocol::Unknown,
        }
    }
}

/// Notification encoding used to deliver the notification to the data
/// collection.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum NotificationEncoding {
    #[serde(rename = "json")]
    Json,

    #[serde(rename = "xml")]
    Xml,

    #[default]
    Unknown,
}

impl NotificationEncoding {
    pub fn from_string(encoding_str: &str) -> Self {
        match encoding_str {
            "json" => NotificationEncoding::Json,
            "ietf-subscribed-notifications:encode-json" => NotificationEncoding::Json,
            "xml" => NotificationEncoding::Xml,
            "ietf-subscribed-notifications:encode-xml" => NotificationEncoding::Xml,
            _ => NotificationEncoding::Unknown,
        }
    }
}

/// Transport protocol used to deliver the notification to the data collection.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum NotificationTransport {
    #[serde(rename = "ssh")]
    SSH,

    #[serde(rename = "http")]
    HTTP,

    #[serde(rename = "udp-notif")]
    UDPNotif,

    #[serde(rename = "https-notif")]
    HTTPSNotif,

    #[default]
    Unknown,
}

impl NotificationTransport {
    pub fn from_string(transport_str: &str) -> Self {
        match transport_str {
            "ssh" => NotificationTransport::SSH,
            "http" => NotificationTransport::HTTP,
            "udp-notif" => NotificationTransport::UDPNotif,
            "ietf-udp-notif-transport:udp-notif" => NotificationTransport::UDPNotif,
            "https-notif" => NotificationTransport::HTTPSNotif,
            "ietf-https-notif-transport:https-notif" => NotificationTransport::HTTPSNotif,
            _ => NotificationTransport::Unknown,
        }
    }
}

/// Generic Metadata Manifest
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Manifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_pen: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_flavor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
}

/// Telemetry Notification Metadata
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct NotificationMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_time: Option<chrono::DateTime<chrono::Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub yang_push_subscription: Option<SubscriptionMetadata>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct SubscriptionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<SubscriptionId>,

    pub filters: YangPushFilters,

    pub module_version: Vec<YangPushModuleVersion>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub yang_library_content_id: Option<String>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushFilters {
    pub stream_filter: Vec<StreamFilter>,

    #[serde(flatten)]
    pub extra_filters: Value,
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
    StreamXpathFilter {
        #[serde(rename = "stream-xpath-filter")]
        #[serde(skip_serializing_if = "Option::is_none")]
        stream_xpath_filter: Option<String>,
    },
    StreamSubtreeFilter {
        #[serde(rename = "stream-subtree-filter")]
        #[serde(skip_serializing_if = "Option::is_none")]
        stream_subtree_filter: Option<Value>,
    },
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct YangPushModuleVersion {
    pub module_name: String,

    pub revision: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct DataCollectionMetadata {
    pub remote_address: IpAddr,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,

    pub labels: Vec<Label>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Label {
    pub name: String,

    #[serde(flatten)]
    pub value: Option<LabelValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum LabelValue {
    StringValue {
        #[serde(rename = "string-values")]
        string_values: String,
    },
    AnydataValue {
        #[serde(rename = "anydata-values")]
        anydata_values: Value,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json;

    #[test]
    fn test_telemetry_message_serde() {
        let original_message = TelemetryMessage {
            timestamp: Utc.timestamp_millis_opt(0).unwrap(),
            notification_protocol: NotificationProtocol::YangPushConfigured,
            notification_encoding: NotificationEncoding::Json,
            notification_transport: NotificationTransport::UDPNotif,
            network_node_manifest: Manifest {
                name: Some("node_id".to_string()),
                vendor: Some("FRR".to_string()),
                vendor_pen: None,
                software_version: None,
                software_flavor: None,
                os_version: None,
                os_type: None,
            },
            data_collection_manifest: Manifest {
                name: Some("dev-collector".to_string()),
                vendor: Some("NetGauze".to_string()),
                vendor_pen: Some(12345),
                software_version: Some("1.0.0".to_string()),
                software_flavor: Some("release".to_string()),
                os_version: Some("8.10".to_string()),
                os_type: Some("Rocky Linux".to_string()),
            },
            telemetry_notification_metadata: NotificationMetadata {
                event_time: None,
                yang_push_subscription: Some(SubscriptionMetadata {
                    id: Some(1),
                    filters: YangPushFilters {
                        stream_filter: vec![
                            StreamFilter::ByReference {
                                stream_filter_name: "example-stream".to_string(),
                            },
                            StreamFilter::WithinSubscription {
                                filter_spec: Some(StreamFilterSpec::StreamSubtreeFilter {
                                    stream_subtree_filter: Some(serde_json::json!({
                                        "filter": "example-subtree-filter"
                                    })),
                                }),
                            },
                        ],
                        extra_filters: serde_json::json!({}),
                    },
                    module_version: vec![YangPushModuleVersion {
                        module_name: "example-module".to_string(),
                        revision: "2025-01-01".to_string(),
                        revision_label: Some("1.0.0".to_string()),
                    }],
                    yang_library_content_id: Some("random-content-id".to_string()),
                }),
            },
            data_collection_metadata: DataCollectionMetadata {
                remote_address: "127.0.0.1".parse().unwrap(),
                remote_port: Some(8080),
                local_address: None,
                local_port: None,
                labels: vec![
                    Label {
                        name: "platform_id".to_string(),
                        value: Some(LabelValue::StringValue {
                            string_values: "IETF LAB".to_string(),
                        }),
                    },
                    Label {
                        name: "test_anykey_label".to_string(),
                        value: Some(LabelValue::AnydataValue {
                            anydata_values: serde_json::json!({"key": "value"}),
                        }),
                    },
                ],
            },
            payload: None,
        };

        // Serialize the TelemetryMessage to JSON
        let serialized = serde_json::to_string(&original_message).expect("Failed to serialize");

        // Expected JSON string
        let expected_json = r#"{"timestamp":"1970-01-01T00:00:00Z","notification-protocol":"yp-configured","notification-encoding":"json","notification-transport":"udp-notif","network-node-manifest":{"name":"node_id","vendor":"FRR"},"data-collection-manifest":{"name":"dev-collector","vendor":"NetGauze","vendor-pen":12345,"software-version":"1.0.0","software-flavor":"release","os-version":"8.10","os-type":"Rocky Linux"},"telemetry-notification-metadata":{"yang-push-subscription":{"id":1,"filters":{"stream-filter":[{"stream-filter-name":"example-stream"},{"stream-subtree-filter":{"filter":"example-subtree-filter"}}]},"module-version":[{"module-name":"example-module","revision":"2025-01-01","revision-label":"1.0.0"}],"yang-library-content-id":"random-content-id"}},"data-collection-metadata":{"remote-address":"127.0.0.1","remote-port":8080,"labels":[{"name":"platform_id","string-values":"IETF LAB"},{"name":"test_anykey_label","anydata-values":{"key":"value"}}]}}"#;

        // Assert that the serialized JSON string matches the expected JSON string
        assert_eq!(
            serialized, expected_json,
            "Serialized JSON does not match the expected JSON"
        );

        // Deserialize the JSON string back to a TelemetryMessage
        let deserialized: TelemetryMessage =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Assert that the original and deserialized messages are equal
        assert_eq!(original_message, deserialized);
    }
}
