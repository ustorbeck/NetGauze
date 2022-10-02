// Copyright (C) 2022-present The NetGauze Authors.
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

//! Deserializer library for BMP's wire protocol

use chrono::{TimeZone, Utc};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    string::FromUtf8Error,
};

use netgauze_bgp_pkt::{serde::deserializer::BGPMessageParsingError, BGPMessage};
use nom::{
    error::ErrorKind,
    number::complete::{be_u128, be_u16, be_u32, be_u64, be_u8},
    IResult,
};

use netgauze_parse_utils::{
    parse_into_located, parse_till_empty_into_located,
    parse_till_empty_into_with_one_input_located, ReadablePDU, Span,
};
use netgauze_serde_macros::LocatedError;

use crate::{
    iana::{
        BmpMessageType, InitiationInformationTlvType, UndefinedBmpMessageType,
        UndefinedBmpPeerTypeCode, UndefinedInitiationInformationTlvType, BMP_VERSION,
        PEER_FLAGS_IS_ADJ_RIB_OUT, PEER_FLAGS_IS_ASN2, PEER_FLAGS_IS_FILTERED, PEER_FLAGS_IS_IPV6,
        PEER_FLAGS_IS_POST_POLICY,
    },
    BmpMessage, BmpPeerType, BmpPeerTypeCode, InitiationInformation, InitiationMessage, PeerHeader,
    RouteMonitoringMessage,
};

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum BmpMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    UnsupportedBmpVersion(u8),
    UndefinedBmpMessageType(#[from_external] UndefinedBmpMessageType),
    UndefinedPeerType(#[from_external] UndefinedBmpPeerTypeCode),
    RouteMonitoringMessageError(
        #[from_located(module = "self")] RouteMonitoringMessageParsingError,
    ),
    InitiationMessageError(#[from_located(module = "self")] InitiationMessageParsingError),
}

impl<'a> ReadablePDU<'a, LocatedBmpMessageParsingError<'a>> for BmpMessage {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedBmpMessageParsingError<'a>> {
        let input = buf;
        let (buf, version) = be_u8(buf)?;
        if version != BMP_VERSION {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                input,
                BmpMessageParsingError::UnsupportedBmpVersion(version),
            )));
        }
        let (buf, length) = be_u32(buf)?;
        let (reminder, buf) = nom::bytes::complete::take(length - 5)(buf)?;
        let (buf, msg_type) = nom::combinator::map_res(be_u8, BmpMessageType::try_from)(buf)?;
        let (buf, msg) = match msg_type {
            BmpMessageType::RouteMonitoring => {
                let (buf, value) = parse_into_located(buf)?;
                (buf, BmpMessage::RouteMonitoring(value))
            }
            BmpMessageType::StatisticsReport => todo!(),
            BmpMessageType::PeerDownNotification => todo!(),
            BmpMessageType::PeerUpNotification => todo!(),
            BmpMessageType::Initiation => {
                let (buf, init) = parse_into_located(buf)?;
                (buf, BmpMessage::Initiation(init))
            }
            BmpMessageType::Termination => todo!(),
            BmpMessageType::RouteMirroring => todo!(),
            BmpMessageType::Experimental251 => (buf, BmpMessage::Experimental251(buf.to_vec())),
            BmpMessageType::Experimental252 => (buf, BmpMessage::Experimental252(buf.to_vec())),
            BmpMessageType::Experimental253 => (buf, BmpMessage::Experimental253(buf.to_vec())),
            BmpMessageType::Experimental254 => (buf, BmpMessage::Experimental254(buf.to_vec())),
        };
        // Make sure bmp message is fully parsed according to it's length
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedBmpMessageParsingError::new(
                buf,
                BmpMessageParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((reminder, msg))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum InitiationMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    InitiationInformationError(#[from_located(module = "self")] InitiationInformationParsingError),
}

impl<'a> ReadablePDU<'a, LocatedInitiationMessageParsingError<'a>> for InitiationMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedInitiationMessageParsingError<'a>> {
        let (buf, information) = parse_till_empty_into_located(buf)?;
        Ok((buf, InitiationMessage::new(information)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum InitiationInformationParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedType(#[from_external] UndefinedInitiationInformationTlvType),
    FromUtf8Error(FromUtf8Error),
}

impl<'a> ReadablePDU<'a, LocatedInitiationInformationParsingError<'a>> for InitiationInformation {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedInitiationInformationParsingError<'a>> {
        let (buf, tlv_type) =
            nom::combinator::map_res(be_u16, InitiationInformationTlvType::try_from)(buf)?;
        let (buf, length) = be_u16(buf)?;
        let (reminder, buf) = nom::bytes::complete::take(length)(buf)?;
        match tlv_type {
            InitiationInformationTlvType::String => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::String(str)))
            }
            InitiationInformationTlvType::SystemDescription => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::SystemDescription(str)))
            }
            InitiationInformationTlvType::SystemName => {
                let str = match String::from_utf8(buf.to_vec()) {
                    Ok(str) => str,
                    Err(err) => {
                        return Err(nom::Err::Error(
                            LocatedInitiationInformationParsingError::new(
                                buf,
                                InitiationInformationParsingError::FromUtf8Error(err),
                            ),
                        ))
                    }
                };
                Ok((reminder, InitiationInformation::SystemName(str)))
            }
            InitiationInformationTlvType::VrfTableName => todo!(),
            InitiationInformationTlvType::AdminLabel => todo!(),
            InitiationInformationTlvType::Experimental65531 => todo!(),
            InitiationInformationTlvType::Experimental65532 => todo!(),
            InitiationInformationTlvType::Experimental65533 => todo!(),
            InitiationInformationTlvType::Experimental65534 => todo!(),
        }
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum RouteMonitoringMessageParsingError {
    NomError(#[from_nom] ErrorKind),
    PeerHeaderError(#[from_located(module = "self")] PeerHeaderParsingError),
    BgpMessageError(
        #[from_located(module = "netgauze_bgp_pkt::serde::deserializer")] BGPMessageParsingError,
    ),
}

impl<'a> ReadablePDU<'a, LocatedRouteMonitoringMessageParsingError<'a>> for RouteMonitoringMessage {
    fn from_wire(
        buf: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedRouteMonitoringMessageParsingError<'a>> {
        let (buf, peer_header) = parse_into_located(buf)?;
        let (buf, bgp_messages): (Span<'a>, Vec<BGPMessage>) =
            parse_till_empty_into_with_one_input_located(buf, true)?;
        let mut updates = vec![];
        for msg in bgp_messages {
            match msg {
                BGPMessage::Open(_) => {}
                BGPMessage::Update(update) => {
                    updates.push(update);
                }
                BGPMessage::Notification(_) => {}
                BGPMessage::KeepAlive => {}
                BGPMessage::RouteRefresh(_) => {}
            }
        }
        Ok((buf, RouteMonitoringMessage::new(peer_header, updates)))
    }
}

#[derive(LocatedError, Eq, PartialEq, Clone, Debug)]
pub enum PeerHeaderParsingError {
    NomError(#[from_nom] ErrorKind),
    UndefinedBmpPeerTypeCode(#[from_external] UndefinedBmpPeerTypeCode),
}

impl<'a> ReadablePDU<'a, LocatedPeerHeaderParsingError<'a>> for PeerHeader {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedPeerHeaderParsingError<'a>> {
        let (buf, peer_type) = nom::combinator::map_res(be_u8, BmpPeerTypeCode::try_from)(buf)?;
        let (buf, peer_flags) = be_u8(buf)?;
        let ipv6 = peer_flags & PEER_FLAGS_IS_IPV6 == PEER_FLAGS_IS_IPV6;
        let post_policy = peer_flags & PEER_FLAGS_IS_POST_POLICY == PEER_FLAGS_IS_POST_POLICY;
        let asn2 = peer_flags & PEER_FLAGS_IS_ASN2 == PEER_FLAGS_IS_ASN2;
        let adj_rib_out = peer_flags & PEER_FLAGS_IS_ADJ_RIB_OUT == PEER_FLAGS_IS_ADJ_RIB_OUT;
        let filtered = peer_flags & PEER_FLAGS_IS_FILTERED == PEER_FLAGS_IS_FILTERED;
        let (buf, distinguisher) = be_u64(buf)?;
        let distinguisher = if distinguisher == 0 {
            None
        } else {
            Some(distinguisher)
        };
        let (buf, peer_address) = be_u128(buf)?;
        let address = if peer_address == 0u128 {
            None
        } else if ipv6 {
            Some(IpAddr::V6(Ipv6Addr::from(peer_address)))
        } else {
            Some(IpAddr::V4(Ipv4Addr::from(peer_address as u32)))
        };
        let (buf, peer_as) = be_u32(buf)?;
        let (buf, bgp_id) = be_u32(buf)?;
        let bgp_id = Ipv4Addr::from(bgp_id);
        let (buf, timestamp_secs) = be_u32(buf)?;
        let (buf, timestamp_milli) = be_u32(buf)?;
        let time = if timestamp_secs != 0 && timestamp_milli != 0 {
            Some(Utc.timestamp(timestamp_secs.into(), timestamp_milli * 1000))
        } else {
            None
        };

        let peer_header = match peer_type {
            BmpPeerTypeCode::GlobalInstancePeer => PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6,
                    post_policy,
                    asn2,
                    adj_rib_out,
                },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::RDInstancePeer => PeerHeader::new(
                BmpPeerType::RdInstancePeer {
                    ipv6,
                    post_policy,
                    asn2,
                    adj_rib_out,
                },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::LocalInstancePeer => PeerHeader::new(
                BmpPeerType::LocalInstancePeer {
                    ipv6,
                    post_policy,
                    asn2,
                    adj_rib_out,
                },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::LocRibInstancePeer => PeerHeader::new(
                BmpPeerType::LocRibInstance { filtered },
                distinguisher,
                address,
                peer_as,
                bgp_id,
                time,
            ),
            BmpPeerTypeCode::Experimental251 => todo!(),
            BmpPeerTypeCode::Experimental252 => todo!(),
            BmpPeerTypeCode::Experimental253 => todo!(),
            BmpPeerTypeCode::Experimental254 => todo!(),
        };
        Ok((buf, peer_header))
    }
}
