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

// TODO: documentation here...
// TODO: testing: integrate in the pcap_tests (serde with this structs
// definitions to check if all messages are recomposed the same way after
// deserialization!)       --> also add a small tests here in the file for
// this...

/// References:
/// - https://datatracker.ietf.org/doc/html/rfc8639
/// - https://datatracker.ietf.org/doc/html/rfc8641
/// - https://datatracker.ietf.org/doc/html/draft-ietf-netconf-yang-notifications-versioning-08
use crate::telemetry::{SubscriptionId, YangPushModuleVersion};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Notification Variants
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Subscription Started and Modified Message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionStartedModified {
    id: SubscriptionId,

    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<String>,

    #[serde(rename = "ietf-yang-push-revision:module-version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    module_version: Option<Vec<YangPushModuleVersion>>,

    #[serde(rename = "ietf-yang-push-revision:content-id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    content_id: Option<String>,

    #[serde(rename = "ietf-yang-push:datastore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    datastore: Option<String>,

    #[serde(rename = "ietf-yang-push:datastore-xpath-filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    datastore_xpath_filter: Option<String>,

    #[serde(rename = "stream")]
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<String>,

    #[serde(rename = "stream-xpath-filter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_xpath_filter: Option<String>,

    #[serde(flatten)]
    extra_fields: Value,
}

impl SubscriptionStartedModified {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
    pub fn encoding(&self) -> Option<&String> {
        self.encoding.as_ref()
    }
    pub fn transport(&self) -> Option<&String> {
        self.transport.as_ref()
    }
    pub fn module_version(&self) -> Option<&Vec<YangPushModuleVersion>> {
        self.module_version.as_ref()
    }
    pub fn content_id(&self) -> Option<&String> {
        self.content_id.as_ref()
    }
    pub fn datastore(&self) -> Option<&String> {
        self.datastore.as_ref()
    }
    pub fn datastore_xpath_filter(&self) -> Option<&String> {
        self.datastore_xpath_filter.as_ref()
    }
    pub fn stream(&self) -> Option<&String> {
        self.stream.as_ref()
    }
    pub fn stream_xpath_filter(&self) -> Option<&String> {
        self.stream_xpath_filter.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionTerminated {
    id: SubscriptionId,

    reason: String,

    #[serde(flatten)]
    extra_fields: Value,
}

impl SubscriptionTerminated {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YangPushUpdate {
    id: SubscriptionId,

    #[serde(rename = "datastore-contents")]
    datastore_contents: Value,

    #[serde(flatten)]
    extra_fields: Value,
}

impl YangPushUpdate {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
}
