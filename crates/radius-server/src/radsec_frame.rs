//! RFC 6614 constants and stream framing shared by the RadSec listener
//! (inbound, `radsec.rs`) and the outbound RadSec link to proxy home servers
//! (`proxy::radsec_client`).
//!
//! This module has no TLS dependency so it is always compiled: the proxy's
//! home-server validation needs [`RADSEC_SECRET`] whether or not the `tls`
//! feature is on.

/// RFC 6614 §2.3 item 4: RadSec uses a fixed shared secret of the ASCII string
/// `"radsec"` for the RADIUS Authenticator / Message-Authenticator computations.
/// It authenticates nothing — the TLS layer does — which is why it is public.
pub(crate) const RADSEC_SECRET: &[u8] = b"radsec";

/// A RADIUS packet header is 20 octets; the `Length` field is octets 2..4.
pub const RADIUS_HEADER_LEN: usize = 20;

/// RFC 2865 §3: the RADIUS `Length` field ranges 20..=4096.
pub const RADIUS_MIN_LEN: usize = RADIUS_HEADER_LEN;
pub const RADIUS_MAX_LEN: usize = 4096;

/// Errors delimiting RADIUS packets on a RadSec stream.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// RFC 2865 §3 bounds the `Length` field to 20..=4096; a stream carrying
    /// anything else has lost synchronisation and RFC 6613 §2.6.4 says the
    /// connection MUST be closed.
    #[error("invalid RADIUS Length field: {0} (must be {RADIUS_MIN_LEN}..={RADIUS_MAX_LEN})")]
    BadRadiusLength(usize),
}

/// Pull one complete RADIUS frame off the front of `buf`, or `None` if a full
/// frame isn't buffered yet. RFC 6614 §3.4 item 1: RADIUS packets are sent
/// as-is on the stream and their boundaries are found by evaluating the
/// `Length` header field; the receiver rules for a bad `Length` are RFC 6613
/// §2.6.4 (close the connection).
pub fn take_frame(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, FrameError> {
    if buf.len() < RADIUS_HEADER_LEN {
        return Ok(None);
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if !(RADIUS_MIN_LEN..=RADIUS_MAX_LEN).contains(&length) {
        return Err(FrameError::BadRadiusLength(length));
    }
    if buf.len() < length {
        return Ok(None);
    }
    Ok(Some(buf.drain(..length).collect()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// A RADIUS header for code 2, identifier `id`, and the given `Length`.
    fn header(id: u8, length: u16) -> Vec<u8> {
        let mut h = vec![2, id];
        h.extend_from_slice(&length.to_be_bytes());
        h.extend_from_slice(&[0u8; 16]);
        h
    }

    #[test]
    fn incomplete_header_yields_none_and_keeps_bytes() {
        let mut buf = header(1, 20);
        buf.truncate(19);
        assert_eq!(take_frame(&mut buf).unwrap(), None);
        assert_eq!(buf.len(), 19, "partial header must stay buffered");
    }

    #[test]
    fn exact_frame_is_taken_and_buffer_emptied() {
        let mut buf = header(7, 20);
        let frame = take_frame(&mut buf).unwrap().expect("one full frame");
        assert_eq!(frame.len(), 20);
        assert_eq!(frame[1], 7);
        assert!(buf.is_empty());
        assert_eq!(take_frame(&mut buf).unwrap(), None);
    }

    #[test]
    fn two_frames_in_one_buffer_come_out_in_order() {
        let mut buf = header(1, 22);
        buf.extend_from_slice(&[0xaa, 0xbb]);
        buf.extend_from_slice(&header(2, 20));

        let first = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(first.len(), 22);
        assert_eq!(first[1], 1);
        assert_eq!(&first[20..], &[0xaa, 0xbb]);

        let second = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(second.len(), 20);
        assert_eq!(second[1], 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_split_across_reads_completes_on_the_second() {
        let full = {
            let mut f = header(3, 26);
            f.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
            f
        };
        let mut buf = full[..23].to_vec();
        assert_eq!(
            take_frame(&mut buf).unwrap(),
            None,
            "header seen, body incomplete"
        );
        buf.extend_from_slice(&full[23..]);
        assert_eq!(take_frame(&mut buf).unwrap(), Some(full));
        assert!(buf.is_empty());
    }

    #[test]
    fn length_below_minimum_is_an_error() {
        let mut buf = header(1, 19);
        assert_eq!(
            take_frame(&mut buf).unwrap_err(),
            FrameError::BadRadiusLength(19)
        );
    }

    #[test]
    fn length_above_maximum_is_an_error() {
        let mut buf = header(1, 4097);
        assert_eq!(
            take_frame(&mut buf).unwrap_err(),
            FrameError::BadRadiusLength(4097)
        );
    }

    #[test]
    fn minimum_length_is_a_bare_header_frame() {
        let mut buf = header(9, 20);
        buf.extend_from_slice(&[0xff]); // start of the next frame
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.len(), 20);
        assert_eq!(buf, vec![0xff]);
    }

    #[test]
    fn maximum_length_frame_is_accepted() {
        let mut buf = header(1, 4096);
        buf.resize(4096, 0);
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.len(), 4096);
        assert!(buf.is_empty());
    }

    #[test]
    fn radsec_secret_is_the_rfc_6614_fixed_string() {
        // RFC 6614 §2.3 item 4.
        assert_eq!(RADSEC_SECRET, b"radsec");
    }
}
