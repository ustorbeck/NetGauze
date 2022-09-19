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

use crate::{
    capabilities::{
        BGPCapability, ExperimentalCapability, ExperimentalCapabilityCode, FourOctetASCapability,
        UnrecognizedCapability,
    },
    serde::{
        deserializer::capabilities::{
            BGPCapabilityParsingError, FourOctetASCapabilityParsingError,
            LocatedBGPCapabilityParsingError,
        },
        serializer::capabilities::BGPCapabilityWritingError,
    },
};
use netgauze_parse_utils::{
    test_helpers::{test_parse_error, test_parsed_completely, test_write},
    Span,
};
use nom::error::ErrorKind;

#[test]
fn test_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x02, 0x00];
    let bad_wire = [0x02, 1];

    let good = BGPCapability::RouteRefresh;
    let bad = LocatedBGPCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        BGPCapabilityParsingError::InvalidRouteRefreshLength(1),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPCapability, LocatedBGPCapabilityParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_enhanced_route_refresh() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x46, 0x00];
    let bad_wire = [0x46, 1];

    let good = BGPCapability::EnhancedRouteRefresh;
    let bad = LocatedBGPCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_wire[1..]) },
        BGPCapabilityParsingError::InvalidEnhancedRouteRefreshLength(1),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPCapability, LocatedBGPCapabilityParsingError<'_>>(&bad_wire, &bad);
    test_write(&good, &good_wire)?;

    Ok(())
}

#[test]
fn test_unrecognized_capability() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x80, 0x01, 0x01];

    let good = BGPCapability::Unrecognized(UnrecognizedCapability::new(128, vec![1]));

    test_parsed_completely(&good_wire, &good);
    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_four_octet_as() -> Result<(), BGPCapabilityWritingError> {
    let good_wire = [0x41, 0x04, 0x00, 0x00, 0x00, 0x064];
    let invalid_length_wire = [0x41, 0x03, 0x00, 0x00, 0x00, 0x064];
    let bad_incomplete_wire = [0x41, 0x04, 0x00, 0x00, 0x00];

    let good = BGPCapability::FourOctetAS(FourOctetASCapability::new(100));
    let invalid_length = LocatedBGPCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &invalid_length_wire[1..]) },
        BGPCapabilityParsingError::FourOctetASCapabilityError(
            FourOctetASCapabilityParsingError::InvalidLength(invalid_length_wire[1]),
        ),
    );
    let bad_incomplete = LocatedBGPCapabilityParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_incomplete_wire[2..]) },
        BGPCapabilityParsingError::FourOctetASCapabilityError(
            FourOctetASCapabilityParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<BGPCapability, LocatedBGPCapabilityParsingError<'_>>(
        &invalid_length_wire,
        &invalid_length,
    );
    test_parse_error::<BGPCapability, LocatedBGPCapabilityParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_experimental_capabilities() -> Result<(), BGPCapabilityWritingError> {
    // IANA defines the codes 239-254 as reserved for Experimental Use
    for code in 239..255 {
        let good_wire = [code, 0x01, 0x01];

        let code = ExperimentalCapabilityCode::from_repr(code).unwrap();
        let good = BGPCapability::Experimental(ExperimentalCapability::new(code, vec![1]));

        test_parsed_completely(&good_wire, &good);
        test_write(&good, &good_wire)?;
    }
    Ok(())
}
