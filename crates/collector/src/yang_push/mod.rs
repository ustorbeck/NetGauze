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

use crate::notification::*; // TODO: restrict to only what is needed
use crate::telemetry::*; // TODO: restrict to only what is needed
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod enrichment;
pub mod notification;
pub mod notification_v2; // Not fully working fine at the moment...
pub mod telemetry;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UdpNotifPayload {
    #[serde(rename = "ietf-notification:notification")]
    Notification(Notification),

    Unknown(Bytes),
}

/// Cache for YangPush subscriptions metadata
pub type SubscriptionsCache = HashMap<SubscriptionId, SubscriptionInformation>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionInformation {
    pub encoding: NotificationEncoding,
    pub transport: NotificationTransport,
    pub subscription_metadata: SubscriptionMetadata,
}
