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
    path_attribute::{
        AS4Path, ASPath, As2PathSegment, As4PathSegment, AsPathSegmentType, NextHop, Origin,
        PathAttribute, PathAttributeLength, UndefinedAsPathSegmentType, UndefinedOrigin,
    },
    serde::{
        deserializer::path_attribute::{
            AsPathParsingError, LocatedAsPathParsingError, LocatedNextHopParsingError,
            LocatedOriginParsingError, LocatedPathAttributeParsingError, NextHopParsingError,
            OriginParsingError, PathAttributeParsingError,
        },
        serializer::path_attribute::{
            AsPathWritingError, NextHopWritingError, OriginWritingError, PathAttributeWritingError,
        },
    },
};
use netgauze_parse_utils::{
    test_helpers::{
        test_parse_error, test_parse_error_with_one_input, test_parse_error_with_two_inputs,
        test_parsed_completely, test_parsed_completely_with_one_input,
        test_parsed_completely_with_two_inputs, test_write, test_write_with_one_input,
    },
    Span,
};
use std::net::Ipv4Addr;

#[test]
fn test_origin_value() -> Result<(), OriginWritingError> {
    let good_igp_wire = [0x01, 0x00];
    let good_egp_wire = [0x01, 0x01];
    let good_incomplete_wire = [0x01, 0x02];
    let bad_zero_length_wire = [0x0, 0x02];
    let bad_long_length_wire = [0x2, 0x02];
    let bad_invalid_code_wire = [0x1, 0x03];

    let igp = Origin::IGP;
    let egp = Origin::EGP;
    let incomplete = Origin::Incomplete;
    let bad_zero_length = LocatedOriginParsingError::new(
        Span::new(&bad_zero_length_wire),
        OriginParsingError::InvalidOriginLength(PathAttributeLength::U8(0)),
    );

    let bad_long_length = LocatedOriginParsingError::new(
        Span::new(&bad_long_length_wire),
        OriginParsingError::InvalidOriginLength(PathAttributeLength::U8(2)),
    );

    let bad_invalid_code = LocatedOriginParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_invalid_code_wire[1..]) },
        OriginParsingError::UndefinedOrigin(UndefinedOrigin(3)),
    );

    test_parsed_completely_with_one_input(&good_igp_wire, false, &igp);
    test_parsed_completely_with_one_input(&good_egp_wire, false, &egp);
    test_parsed_completely_with_one_input(&good_incomplete_wire, false, &incomplete);
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_zero_length_wire,
        false,
        &bad_zero_length,
    );
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_long_length_wire,
        false,
        &bad_long_length,
    );
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_invalid_code_wire,
        false,
        &bad_invalid_code,
    );

    test_write_with_one_input(&igp, false, &good_igp_wire)?;
    test_write_with_one_input(&egp, false, &good_egp_wire)?;
    test_write_with_one_input(&incomplete, false, &good_incomplete_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_origin() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x01, 0x01, 0x00];
    let good_wire_extended = [0x50, 0x01, 0x00, 0x01, 0x00];
    let bad_wire_extended = [0x50, 0x01, 0x00, 0x01, 0x03];
    let good = PathAttribute::Origin {
        extended_length: false,
        value: Origin::IGP,
    };
    let good_extended = PathAttribute::Origin {
        extended_length: true,
        value: Origin::IGP,
    };

    let bad_extended = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(4, &bad_wire_extended[4..]) },
        PathAttributeParsingError::OriginError(OriginParsingError::UndefinedOrigin(
            UndefinedOrigin(3),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, false, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_wire_extended,
        false,
        &bad_extended,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_as2_path_segment() -> Result<(), AsPathWritingError> {
    let good_set_wire = [0x01, 0x01, 0x00, 0x01];
    let good_seq_wire = [0x02, 0x01, 0x00, 0x01];
    let good_empty_wire = [0x01, 0x00];
    let undefined_segment_type_wire = [0x00, 0x01, 0x00, 0x01];

    let set = As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]);
    let seq = As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]);
    let empty = As2PathSegment::new(AsPathSegmentType::AsSet, vec![]);

    let undefined_segment_type = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &undefined_segment_type_wire) },
        AsPathParsingError::UndefinedAsPathSegmentType(UndefinedAsPathSegmentType(0x00)),
    );

    test_parsed_completely(&good_set_wire, &set);
    test_parsed_completely(&good_seq_wire, &seq);
    test_parsed_completely(&good_empty_wire, &empty);
    test_parse_error::<As2PathSegment, LocatedAsPathParsingError<'_>>(
        &undefined_segment_type_wire,
        &undefined_segment_type,
    );

    test_write(&set, &good_set_wire)?;
    test_write(&seq, &good_seq_wire)?;
    test_write(&empty, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as4_path_segment() -> Result<(), AsPathWritingError> {
    let good_set_wire = [0x01, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_seq_wire = [0x02, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_empty_wire = [0x01, 0x00];
    let undefined_segment_type_wire = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01];

    let set = As4PathSegment::new(AsPathSegmentType::AsSet, vec![1]);
    let seq = As4PathSegment::new(AsPathSegmentType::AsSequence, vec![1]);
    let empty = As4PathSegment::new(AsPathSegmentType::AsSet, vec![]);

    let undefined_segment_type = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &undefined_segment_type_wire) },
        AsPathParsingError::UndefinedAsPathSegmentType(UndefinedAsPathSegmentType(0x00)),
    );

    test_parsed_completely(&good_set_wire, &set);
    test_parsed_completely(&good_seq_wire, &seq);
    test_parsed_completely(&good_empty_wire, &empty);
    test_parse_error::<As4PathSegment, LocatedAsPathParsingError<'_>>(
        &undefined_segment_type_wire,
        &undefined_segment_type,
    );

    test_write(&set, &good_set_wire)?;
    test_write(&seq, &good_seq_wire)?;
    test_write(&empty, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as2_path_segments() -> Result<(), AsPathWritingError> {
    let good_wire = [0x08, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x08, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01];
    let good_empty_wire = [0x00];
    let bad_underflow_wire = [0x08, 0x01, 0x01, 0x00, 0x01];
    let bad_overflow_wire = [0x08, 0x01, 0x02, 0x00, 0x01, 0x00, 0x02];

    let good = ASPath::As2PathSegments(vec![
        As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);
    let good_extended = ASPath::As2PathSegments(vec![
        As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);
    let good_empty = ASPath::As2PathSegments(vec![]);
    let bad_underflow = nom::Err::Incomplete(nom::Needed::new(4));
    let bad_overflow = nom::Err::Incomplete(nom::Needed::new(2));

    test_parsed_completely_with_two_inputs(&good_wire, false, false, &good);
    test_parsed_completely_with_two_inputs(&good_empty_wire, false, false, &good_empty);
    test_parsed_completely_with_two_inputs(&good_extended_wire, true, false, &good_extended);
    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_underflow_wire,
        false,
        false,
        bad_underflow,
    );
    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_overflow_wire,
        false,
        false,
        bad_overflow,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    test_write_with_one_input(&good_empty, false, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as4_path_segments() -> Result<(), AsPathWritingError> {
    let good_empty_wire = [0x00, 0x00];
    let good_one_wire = [0x00, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_two_wire = [
        0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let bad_underflow_wire = [0x00, 0x08, 0x01, 0x01, 0x00, 0x01];
    let bad_overflow_wire = [0x00, 0x08, 0x01, 0x02, 0x00, 0x01, 0x00, 0x02];

    let good_empty = ASPath::As4PathSegments(vec![]);
    let good_one = ASPath::As4PathSegments(vec![As4PathSegment::new(
        AsPathSegmentType::AsSequence,
        vec![1],
    )]);
    let good_two = ASPath::As4PathSegments(vec![
        As4PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As4PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);

    let bad_underflow = nom::Err::Incomplete(nom::Needed::new(4));
    let bad_overflow = nom::Err::Incomplete(nom::Needed::new(2));

    test_parsed_completely_with_two_inputs(&good_empty_wire, true, true, &good_empty);
    test_parsed_completely_with_two_inputs(&good_one_wire, true, true, &good_one);
    test_parsed_completely_with_two_inputs(&good_two_wire, true, true, &good_two);

    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_underflow_wire,
        true,
        true,
        bad_underflow,
    );
    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_overflow_wire,
        true,
        true,
        bad_overflow,
    );

    test_write_with_one_input(&good_empty, true, &good_empty_wire)?;
    test_write_with_one_input(&good_one, true, &good_one_wire)?;
    test_write_with_one_input(&good_two, true, &good_two_wire)?;

    Ok(())
}

#[test]
fn test_path_attribute_as2_path() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x02, 0x06, 0x02, 0x02, 0x00, 0x64, 0x01, 0x2c];
    let good_wire_extended = [0x50, 0x02, 0x00, 0x06, 0x02, 0x02, 0x00, 0x64, 0x01, 0x2c];
    let undefined_segment_type_wire = [0x50, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x64, 0x01, 0x2c];

    let good = PathAttribute::ASPath {
        extended_length: false,
        value: ASPath::As2PathSegments(vec![As2PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_extended = PathAttribute::ASPath {
        extended_length: true,
        value: ASPath::As2PathSegments(vec![As2PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };

    let undefined_segment_type = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(4, &undefined_segment_type_wire[4..]) },
        PathAttributeParsingError::AsPathError(AsPathParsingError::UndefinedAsPathSegmentType(
            UndefinedAsPathSegmentType(0),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, false, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &undefined_segment_type_wire,
        false,
        &undefined_segment_type,
    );
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_path_attribute_as4_path() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x40, 0x02, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_extended = [
        0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];

    let good = PathAttribute::ASPath {
        extended_length: false,
        value: ASPath::As4PathSegments(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_extended = PathAttribute::ASPath {
        extended_length: true,
        value: ASPath::As4PathSegments(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };

    test_parsed_completely_with_one_input(&good_wire, true, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_path_attribute_as4_path_transitional() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x11, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_extended = [
        0xd0, 0x11, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_partial = [
        0xf0, 0x11, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];

    let good = PathAttribute::AS4Path {
        partial: false,
        extended_length: false,
        value: AS4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_extended = PathAttribute::AS4Path {
        partial: false,
        extended_length: true,
        value: AS4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_partial = PathAttribute::AS4Path {
        partial: true,
        extended_length: true,
        value: AS4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_parsed_completely_with_one_input(&good_wire_partial, true, &good_partial);

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    test_write(&good_partial, &good_wire_partial)?;
    Ok(())
}

#[test]
fn test_next_hop() -> Result<(), NextHopWritingError> {
    let good_wire = [0x04, 0xac, 0x10, 0x03, 0x02];
    let bad_wire = [0x05, 0xac, 0x10, 0x03, 0x02];

    let good = NextHop::new(Ipv4Addr::new(172, 16, 3, 2));
    let bad = LocatedNextHopParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_wire) },
        NextHopParsingError::InvalidNextHopLength(PathAttributeLength::U8(5)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<NextHop, bool, LocatedNextHopParsingError<'_>>(
        &bad_wire, false, &bad,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_next_hop() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x03, 0x04, 0xac, 0x10, 0x03, 0x01];
    let good_wire_extended = [0x50, 0x03, 0x00, 0x04, 0xac, 0x10, 0x03, 0x01];
    let bad_wire = [0x50, 0x03, 0x00, 0x03, 0xac, 0x10, 0x03, 0x01];

    let good = PathAttribute::NextHop {
        extended_length: false,
        value: NextHop::new(Ipv4Addr::new(172, 16, 3, 1)),
    };
    let good_extended = PathAttribute::NextHop {
        extended_length: true,
        value: NextHop::new(Ipv4Addr::new(172, 16, 3, 1)),
    };
    let bad = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_wire[2..]) },
        PathAttributeParsingError::NextHopError(NextHopParsingError::InvalidNextHopLength(
            PathAttributeLength::U16(3),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_wire, false, &bad,
    );
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}