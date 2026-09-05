use hp_media::{AccessUnit, HevcDecoder};
/// Explicitly invoked when FFmpeg 7 is installed. Synthetic fixture only.
#[test]
#[ignore = "requires FFmpeg 7 shared libraries in MACVNC_FFMPEG_DIR"]
fn decodes_hevc_444_and_preserves_pts() {
    let mut decoder = HevcDecoder::new().unwrap();
    let data = include_bytes!("fixtures/red-64x48.hevc").to_vec();
    let frames = decoder
        .decode(&AccessUnit {
            generation: 0,
            loss_epoch: 0,
            data,
            tile: 2,
            pts: 42,
            rtp_timestamp: 0,
            donl: 0,
            key: true,
        })
        .unwrap();
    assert_eq!(frames.len(), 1, "low-delay decoder must emit immediately");
    let f = &frames[0];
    assert_eq!(f.tile, 2);
    assert_eq!(f.pts, 42);
    assert_eq!((f.frame.width, f.frame.height), (64, 48));
    assert_eq!(f.frame.pixels.len(), 64 * 48 * 4);
    for px in f.frame.pixels.as_chunks::<4>().0 {
        assert!(px[0] > 230 && px[1] < 20 && px[2] < 20);
        assert_eq!(px[3], 255);
    }
}

#[test]
#[ignore = "requires FFmpeg 7 shared libraries in MACVNC_FFMPEG_DIR"]
fn missing_reference_is_counted_even_when_decoder_emits_a_frame() {
    let data = include_bytes!("fixtures/reference-chain-64x48.hevc");
    let starts: Vec<_> = data
        .windows(6)
        .enumerate()
        .filter(|(_, b)| b[..4] == [0, 0, 0, 1] && b[4] >> 1 & 63 == 35)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(starts.len(), 3);
    let mut d = HevcDecoder::new().unwrap();
    let au = |data: Vec<u8>, pts, key| AccessUnit {
        generation: 0,
        loss_epoch: 0,
        data,
        tile: 0,
        pts,
        rtp_timestamp: 0,
        donl: 0,
        key,
    };
    let first = d
        .decode(&au(data[starts[0]..starts[1]].to_vec(), 0, true))
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(d.take_reference_errors(), 0);
    // Omit the middle reference picture, simulating a completely lost AU.
    let concealed = d.decode(&au(data[starts[2]..].to_vec(), 2, false)).unwrap();
    assert_eq!(
        concealed.len(),
        1,
        "libavcodec conceals and reports decode success"
    );
    assert!(
        d.take_reference_errors() > 0,
        "concealment must trigger recovery telemetry"
    );
    assert_eq!(
        d.take_reference_errors(),
        0,
        "counter is drained exactly once"
    );
}

#[test]
#[ignore = "requires FFmpeg 7 shared libraries in MACVNC_FFMPEG_DIR"]
fn multiple_slices_survive_rtp_assembly_and_match_direct_native_decode() {
    use hp_media::{Depacketizer, RtpPacket};
    let bytes = include_bytes!("fixtures/two-slices-128x128.hevc");
    let mut positions = vec![];
    let mut i = 0;
    while i + 3 < bytes.len() {
        let prefix = if bytes[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if bytes[i..].starts_with(&[0, 0, 1]) {
            3
        } else {
            0
        };
        if prefix > 0 {
            positions.push((i, i + prefix));
            i += prefix;
        } else {
            i += 1;
        }
    }
    let nals: Vec<_> = positions
        .iter()
        .enumerate()
        .map(|(i, (_, start))| {
            &bytes[*start..positions.get(i + 1).map_or(bytes.len(), |(p, _)| *p)]
        })
        .collect();
    let vcl: Vec<_> = nals
        .iter()
        .copied()
        .filter(|n| n[0] >> 1 & 63 <= 31)
        .collect();
    assert_eq!(vcl.len(), 2);
    assert_ne!(vcl[0][2] & 128, 0);
    assert_eq!(vcl[1][2] & 128, 0);
    let mut aggregation = vec![96, 1];
    for nal in nals
        .iter()
        .filter(|n| (32..=34).contains(&(n[0] >> 1 & 63)))
    {
        aggregation.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        aggregation.extend_from_slice(nal);
    }
    let mut depay = Depacketizer::new(1);
    depay.push(
        RtpPacket {
            ssrc: 1,
            seq: 0,
            timestamp: 0,
            marker: false,
            pt: 96,
            payload: aggregation,
        },
        0,
    );
    for (i, nal) in vcl.iter().enumerate() {
        depay.push(
            RtpPacket {
                ssrc: 1,
                seq: i as u16 + 1,
                timestamp: 0,
                marker: i + 1 == vcl.len(),
                pt: 96,
                payload: nal.to_vec(),
            },
            0,
        );
    }
    let units = depay.poll(30);
    assert_eq!(units.len(), 1);
    let mut wire_decoder = HevcDecoder::new().unwrap();
    let wire = wire_decoder.decode(&units[0]).unwrap();
    assert_eq!(wire.len(), 1);
    let mut direct_decoder = HevcDecoder::new().unwrap();
    let direct = direct_decoder
        .decode(&AccessUnit {
            generation: 0,
            loss_epoch: 0,
            data: bytes.to_vec(),
            tile: 0,
            pts: 0,
            rtp_timestamp: 0,
            donl: 0,
            key: true,
        })
        .unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(
        wire[0].frame.pixels, direct[0].frame.pixels,
        "dropping the non-first slice corrupts the lower band"
    );
    assert_eq!(wire_decoder.take_reference_errors(), 0);
    assert_eq!(wire_decoder.take_decode_errors(), 0);
}

#[test]
#[ignore = "requires FFmpeg 7 shared libraries in MACVNC_FFMPEG_DIR"]
fn malformed_parameter_set_reports_non_reference_decoder_error() {
    let mut decoder = HevcDecoder::new().unwrap();
    let _ = decoder.decode(&AccessUnit {
        generation: 0,
        loss_epoch: 0,
        data: vec![0, 0, 0, 1, 66, 1, 0],
        tile: 0,
        pts: 0,
        rtp_timestamp: 0,
        donl: 0,
        key: true,
    });
    assert!(decoder.take_decode_errors() > 0);
    assert_eq!(decoder.take_decode_errors(), 0);
    assert_eq!(decoder.take_reference_errors(), 0);
}
