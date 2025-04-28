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

// TODO: documentation here
// TODO: also add tests from the pcap that produce enriched telemetrymessages!
// TODO: add tests for all the match arms and conditions below...
// TODO: fix error handling / log messages / otel counters...

// TODO: handle subscription terminated which triggers cache removal for the
// subscription....

use crate::{
    notification::{Notification, SubscriptionStartedModified, SubscriptionTerminated},
    yang_push::*,
    SubscriptionInformation, SubscriptionsCache, UdpNotifPayload,
};

use netgauze_udp_notif_pkt::{MediaType, UdpNotifPacket};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use sysinfo::System;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

use colored::*;

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorCommand {
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub enum YangPushEnrichmentActorError {
    EnrichmentChannelClosed,
    YangPushReceiveError,
    YangPushUpdateNoSubscriptionInfo,
    UnsupportedMediaType(MediaType),
    UnknownPayload,
}

impl std::fmt::Display for YangPushEnrichmentActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnrichmentChannelClosed => write!(f, "enrichment channel closed"),
            Self::YangPushReceiveError => write!(f, "error in flow receive channel"),
            Self::YangPushUpdateNoSubscriptionInfo => {
                write!(
                    f,
                    "Yang Push update received but no subscription information found in the cache"
                )
            }
            Self::UnsupportedMediaType(media_type) => {
                write!(f, "Unsupported udp-notif media type: {:?}", media_type)
            }
            Self::UnknownPayload => {
                write!(f, "unknown udp-notif payload format")
            }
        }
    }
}

impl std::error::Error for YangPushEnrichmentActorError {}

#[derive(Debug, Clone)]
pub struct YangPushEnrichmentStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
    pub sent_messages: opentelemetry::metrics::Counter<u64>,
    pub send_error: opentelemetry::metrics::Counter<u64>,
    pub enrichment_error: opentelemetry::metrics::Counter<u64>,
}

impl YangPushEnrichmentStats {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.received.messages")
            .with_description("Number of Yang Push messages received for enrichment")
            .build();
        let sent_messages = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent")
            .with_description("Number of enriched Yang Push messages successfully sent upstream")
            .build();
        let send_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.sent.error")
            .with_description("Number of upstream sending errors")
            .build();
        let enrichment_error = meter
            .u64_counter("netgauze.collector.yang_push.enrichment.error")
            .with_description("Number of Yang Push enrichment errors")
            .build();
        Self {
            received_messages,
            sent_messages,
            send_error,
            enrichment_error,
        }
    }
}

// TODO: make name extendable and/or overwritable from writer_id in
// config (e.g. name = writer_id + "@" + host_name) ?
// TODO: move somewhere else?
fn fetch_sysinfo_manifest() -> Manifest {
    let mut sys = System::new_all();
    sys.refresh_all();

    Manifest {
        name: System::host_name(),
        vendor: Some("NetGauze".to_string()),
        vendor_pen: None,
        software_version: Some(env!("CARGO_PKG_VERSION").to_string()), /* TODO: working also for
                                                                        * binary? */
        software_flavor: Some({
            if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "release".to_string()
            }
        }),
        os_version: System::os_version(),
        os_type: System::name(),
    }
}

struct YangPushEnrichmentActor {
    cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
    udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
    enriched_tx: async_channel::Sender<Arc<TelemetryMessage>>,
    labels: HashMap<IpAddr, (u32, HashMap<String, String>)>,
    default_labels: (u32, HashMap<String, String>),
    subscriptions: HashMap<SocketAddr, SubscriptionsCache>,
    manifest: Manifest,
    stats: YangPushEnrichmentStats,
}

impl YangPushEnrichmentActor {
    fn new(
        cmd_rx: mpsc::Receiver<YangPushEnrichmentActorCommand>,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        enriched_tx: async_channel::Sender<Arc<TelemetryMessage>>,
        stats: YangPushEnrichmentStats,
    ) -> Self {
        let default_labels = (
            0,
            HashMap::from([
                ("pkey".to_string(), "unknown".to_string()),
                ("nkey".to_string(), "unknown".to_string()),
            ]),
        );
        Self {
            cmd_rx,
            udp_notif_rx,
            enriched_tx,
            labels: HashMap::new(),
            default_labels,
            subscriptions: HashMap::new(),
            manifest: fetch_sysinfo_manifest(),
            stats,
        }
    }

    fn cache_subscription(&mut self, peer: SocketAddr, sub: &SubscriptionStartedModified) {
        let transport = match sub.transport() {
            Some(transport_str) => NotificationTransport::from_string(transport_str),
            None => NotificationTransport::Unknown,
        };

        let encoding = match sub.encoding() {
            Some(encoding_str) => NotificationEncoding::from_string(encoding_str),
            None => NotificationEncoding::Unknown,
        };

        let xpath_filter: Option<String> = sub
            .datastore_xpath_filter()
            .cloned()
            .or_else(|| sub.stream_xpath_filter().cloned());

        let subscription_metadata = SubscriptionMetadata {
            id: Some(sub.id()),
            filters: YangPushFilters {
                stream_filter: vec![StreamFilter::WithinSubscription {
                    filter_spec: Some(StreamFilterSpec::StreamXpathFilter {
                        stream_xpath_filter: xpath_filter,
                    }),
                }],
                extra_filters: serde_json::json!({}),
            },
            module_version: sub.module_version().cloned().unwrap_or_default(), /* TODO: test here
                                                                                * default... */
            yang_library_content_id: sub.content_id().cloned(),
        };

        let peer_subscriptions = self.subscriptions.entry(peer).or_insert_with(HashMap::new);

        peer_subscriptions.insert(
            sub.id(),
            SubscriptionInformation {
                encoding,
                transport,
                subscription_metadata,
            },
        );

        // TEMP DEBUG STATEMENT
        debug!(
            "Yang Push subscription cached: {}",
            serde_json::to_string(&self.subscriptions).unwrap().red()
        );
    }

    fn delete_subscription(&mut self, peer: SocketAddr, sub: &SubscriptionTerminated) {
        if let Some(peer_subscriptions) = self.subscriptions.get_mut(&peer) {
            peer_subscriptions.remove(&sub.id());
        }

        // TEMP DEBUG STATEMENT
        debug!(
            "Yang Push subscription cached: {}",
            serde_json::to_string(&self.subscriptions).unwrap().red()
        );
    }

    fn enrich(
        &self,
        peer: SocketAddr,
        subscription_id: &SubscriptionId,
    ) -> Result<TelemetryMessage, YangPushEnrichmentActorError> {
        let timestamp = chrono::Utc::now();

        // Get sonata labels from the cache
        let (_, labels) = self.labels.get(&peer.ip()).unwrap_or(&self.default_labels);
        let labels: Vec<Label> = labels
            .iter()
            .map(|(key, value)| Label {
                name: key.clone(),
                value: Some(LabelValue::StringValue {
                    string_values: value.clone(),
                }),
            })
            .collect();

        // Get subscription information from the cache
        let subscription_information = self
            .subscriptions
            .get(&peer)
            .and_then(|subscriptions| subscriptions.get(subscription_id));

        if let Some(sub_info) = subscription_information {
            // Infer Notification from Transport
            let notification_protocol = match sub_info.transport {
                NotificationTransport::UDPNotif | NotificationTransport::HTTPSNotif => {
                    NotificationProtocol::YangPushConfigured
                }
                _ => NotificationProtocol::Unknown,
            };

            // Populate metadata in a new TelemetryMessage
            Ok(TelemetryMessage {
                timestamp,
                notification_protocol,
                notification_encoding: sub_info.encoding.clone(),
                notification_transport: sub_info.transport.clone(),
                network_node_manifest: Manifest::default(),
                data_collection_manifest: self.manifest.clone(),
                telemetry_notification_metadata: NotificationMetadata {
                    event_time: None,
                    yang_push_subscription: Some(sub_info.subscription_metadata.clone()),
                },
                data_collection_metadata: DataCollectionMetadata {
                    remote_address: peer.ip(),
                    remote_port: Some(peer.port()),
                    local_address: None,
                    local_port: None,
                    labels,
                },
                payload: None,
            })
        } else {
            // TODO: otel counter
            warn!("Yang Push update received but no subscription information found in the cache");
            return Err(YangPushEnrichmentActorError::YangPushUpdateNoSubscriptionInfo);
        }
    }

    // TODO: rethink this function and the return values...
    fn process_notification(
        &mut self,
        peer: SocketAddr,
        message: Notification,
    ) -> Result<Option<TelemetryMessage>, YangPushEnrichmentActorError> {
        // TEMP DEBUG STATEMENT (Notification message)
        // debug!("{}", serde_json::to_string(&message).unwrap().yellow());

        //TODO: add counters (here or in the functions? let's see...)
        match message.notification() {
            NotificationVariant::SubscriptionStarted(sub_started) => {
                debug!(
                    "Received Subscription Started Message (peer: {}, id={})",
                    peer,
                    sub_started.id()
                );
                self.cache_subscription(peer, sub_started);
                return Ok(None);
            }
            NotificationVariant::SubscriptionModified(sub_modified) => {
                debug!(
                    "Received Subscription Modified Message (peer: {}, id={})",
                    peer,
                    sub_modified.id()
                );
                self.cache_subscription(peer, sub_modified);
                return Ok(None);
            }
            NotificationVariant::SubscriptionTerminated(sub_terminated) => {
                debug!(
                    "Received Subscription Terminated Message (peer: {}, id={})",
                    peer,
                    sub_terminated.id()
                );
                self.delete_subscription(peer, sub_terminated);
                return Ok(None);
            }
            NotificationVariant::YangPushUpdate(push_update) => {
                debug!(
                    "Received Yang Push Update Message (peer: {}, id={})",
                    peer,
                    push_update.id()
                );
                let mut telemetry_message = self.enrich(peer, &push_update.id())?;
                telemetry_message.payload = Some(serde_json::to_value(message).unwrap()); // TODO: handle unwrap
                return Ok(Some(telemetry_message));
            }
        }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(YangPushEnrichmentActorCommand::Shutdown) => {
                            info!("Shutting down Yang Push enrichment actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            warn!("Yang Push enrichment actor terminated due to command channel closing");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.udp_notif_rx.recv() => {
                    match msg {
                        Ok(arc_tuple) => {
                            let (peer, udp_notif_pkt) = &*arc_tuple;
                            let peer_tags = [
                                opentelemetry::KeyValue::new(
                                    "network.peer.address",
                                    format!("{}", peer.ip()),
                                ),
                                opentelemetry::KeyValue::new(
                                    "network.peer.port",
                                    opentelemetry::Value::I64(peer.port().into()),
                                ),
                            ];
                            self.stats.received_messages.add(1, &peer_tags);

                            // TODO: investigate maybe calling the msg processing asynchronously
                            //       to avoid blocking if processing one message takes too long...
                            //       --> split payload decoding and notification processing ?

                            // Access the notification from the UdpNotifPacket
                            let payload: UdpNotifPayload;
                            match udp_notif_pkt.media_type() {
                                MediaType::YangDataJson => {
                                    payload = serde_json::from_slice(udp_notif_pkt.payload())?;
                                }
                                MediaType::YangDataXml => {
                                    let payload_str = std::str::from_utf8(udp_notif_pkt.payload())?;
                                    payload = serde_json::from_str(payload_str)?;
                                }
                                MediaType::YangDataCbor => {
                                    payload = ciborium::de::from_reader(std::io::Cursor::new(udp_notif_pkt.payload()))?;
                                }
                                media_type => {
                                    //TODO: log payload to trace?
                                    payload = UdpNotifPayload::Unknown(udp_notif_pkt.payload().clone());
                                    Err(YangPushEnrichmentActorError::UnsupportedMediaType(media_type))?;
                                }
                            }

                            // Process the notification
                            //TODO: here think about handling & what to log (not the best at the moment....)
                            if let UdpNotifPayload::Notification(notification) = payload {
                              match self.process_notification(*peer, notification) {
                                  Ok(Some(enriched)) => {

                                      // TEMP DEBUG STATEMENT
                                      info!("{}", serde_json::to_string(&enriched).unwrap().purple());

                                      // Successfully processed and got a TelemetryMessage
                                      let enriched = std::sync::Arc::new(enriched);
                                      if let Err(err) = self.enriched_tx.send(enriched).await {
                                          error!("YangPushEnrichmentActor send error: {err}");
                                          self.stats.send_error.add(1, &peer_tags);
                                      } else {
                                          self.stats.sent_messages.add(1, &peer_tags);
                                      }
                                  }
                                  Ok(None) => {
                                      debug!("Subscription cache updated: {}", peer);
                                  }
                                  Err(err) => {
                                      warn!("Error processing notification: {err}");
                                      self.stats.enrichment_error.add(1, &peer_tags);
                                  }
                              }
                          } else {
                              Err(YangPushEnrichmentActorError::UnknownPayload)?;
                          }
                        }
                        Err(err) => {
                            error!("Shutting down due to FlowEnrichment recv error: {err}");
                            Err(YangPushEnrichmentActorError::YangPushReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum YangPushEnrichmentActorHandleError {
    SendError,
}
impl std::fmt::Display for YangPushEnrichmentActorHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YangPushEnrichmentActorHandleError::SendError => {
                write!(f, "Failed to send yang-push enrichment actor")
            }
        }
    }
}

impl std::error::Error for YangPushEnrichmentActorHandleError {}

#[derive(Debug, Clone)]
pub struct YangPushEnrichmentActorHandle {
    cmd_send: mpsc::Sender<YangPushEnrichmentActorCommand>,
    enriched_rx: async_channel::Receiver<Arc<TelemetryMessage>>,
}

impl YangPushEnrichmentActorHandle {
    pub fn new(
        buffer_size: usize,
        udp_notif_rx: async_channel::Receiver<Arc<(SocketAddr, UdpNotifPacket)>>,
        stats: either::Either<opentelemetry::metrics::Meter, YangPushEnrichmentStats>,
    ) -> (JoinHandle<anyhow::Result<String>>, Self) {
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let (enriched_tx, enriched_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => YangPushEnrichmentStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = YangPushEnrichmentActor::new(cmd_recv, udp_notif_rx, enriched_tx, stats);
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_send,
            enriched_rx,
        };
        (join_handle, handle)
    }

    pub async fn shutdown(&self) -> Result<(), YangPushEnrichmentActorHandleError> {
        self.cmd_send
            .send(YangPushEnrichmentActorCommand::Shutdown)
            .await
            .map_err(|_| YangPushEnrichmentActorHandleError::SendError)
    }

    pub fn subscribe(&self) -> async_channel::Receiver<Arc<TelemetryMessage>> {
        self.enriched_rx.clone()
    }
}
