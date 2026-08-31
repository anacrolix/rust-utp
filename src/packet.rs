//! uTP version 1 wire format (PacketFormatV1 in libutp).
//!
//! ```text
//! 0       4       8               16              24              32
//! +-------+-------+---------------+---------------+---------------+
//! | type  | ver   | extension     | connection_id                 |
//! +-------+-------+---------------+---------------+---------------+
//! | timestamp_microseconds                                        |
//! +---------------+---------------+---------------+---------------+
//! | timestamp_difference_microseconds                             |
//! +---------------+---------------+---------------+---------------+
//! | wnd_size                                                      |
//! +---------------+---------------+---------------+---------------+
//! | seq_nr                        | ack_nr                        |
//! +---------------+---------------+---------------+---------------+
//! ```

pub const HEADER_SIZE: usize = 20;

pub const ST_DATA: u8 = 0; // Data packet.
pub const ST_FIN: u8 = 1; // Finalize the connection. This is the last packet.
pub const ST_STATE: u8 = 2; // State packet. Used to transmit an ACK with no data.
pub const ST_RESET: u8 = 3; // Terminate connection forcefully.
pub const ST_SYN: u8 = 4; // Connect SYN
pub const ST_NUM_STATES: u8 = 5; // used for bounds checking

/// Accessors over a raw uTP v1 header. All multi-byte fields are big-endian.
#[derive(Clone, Copy)]
pub struct Header<'a>(pub &'a [u8]);

impl<'a> Header<'a> {
    pub fn version(&self) -> u8 {
        self.0[0] & 0xf
    }
    pub fn packet_type(&self) -> u8 {
        self.0[0] >> 4
    }
    pub fn ext(&self) -> u8 {
        self.0[1]
    }
    pub fn conn_id(&self) -> u16 {
        u16::from_be_bytes([self.0[2], self.0[3]])
    }
    pub fn tv_usec(&self) -> u32 {
        u32::from_be_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }
    pub fn reply_micro(&self) -> u32 {
        u32::from_be_bytes([self.0[8], self.0[9], self.0[10], self.0[11]])
    }
    pub fn window_size(&self) -> u32 {
        u32::from_be_bytes([self.0[12], self.0[13], self.0[14], self.0[15]])
    }
    pub fn seq_nr(&self) -> u16 {
        u16::from_be_bytes([self.0[16], self.0[17]])
    }
    pub fn ack_nr(&self) -> u16 {
        u16::from_be_bytes([self.0[18], self.0[19]])
    }

    /// Port of libutp's UTP_Version: sanity checks that make a buffer look
    /// like a v1 packet at all.
    pub fn wire_version(&self) -> u8 {
        if self.packet_type() < ST_NUM_STATES && self.ext() < 3 {
            self.version()
        } else {
            0
        }
    }
}

/// In-place setters for building outgoing packets whose header lives at the
/// front of a byte buffer.
pub fn set_version_type(b: &mut [u8], version: u8, packet_type: u8) {
    b[0] = (packet_type << 4) | (version & 0xf);
}
pub fn set_ext(b: &mut [u8], ext: u8) {
    b[1] = ext;
}
pub fn set_conn_id(b: &mut [u8], id: u16) {
    b[2..4].copy_from_slice(&id.to_be_bytes());
}
pub fn set_tv_usec(b: &mut [u8], v: u32) {
    b[4..8].copy_from_slice(&v.to_be_bytes());
}
pub fn set_reply_micro(b: &mut [u8], v: u32) {
    b[8..12].copy_from_slice(&v.to_be_bytes());
}
pub fn set_window_size(b: &mut [u8], v: u32) {
    b[12..16].copy_from_slice(&v.to_be_bytes());
}
pub fn set_seq_nr(b: &mut [u8], v: u16) {
    b[16..18].copy_from_slice(&v.to_be_bytes());
}
pub fn set_ack_nr(b: &mut [u8], v: u16) {
    b[18..20].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut b = [0u8; HEADER_SIZE];
        set_version_type(&mut b, 1, ST_SYN);
        set_ext(&mut b, 2);
        set_conn_id(&mut b, 0xabcd);
        set_tv_usec(&mut b, 0xdead_beef);
        set_reply_micro(&mut b, 0x0102_0304);
        set_window_size(&mut b, 1 << 20);
        set_seq_nr(&mut b, 0x1234);
        set_ack_nr(&mut b, 0x4321);
        let h = Header(&b);
        assert_eq!(h.version(), 1);
        assert_eq!(h.packet_type(), ST_SYN);
        assert_eq!(h.ext(), 2);
        assert_eq!(h.conn_id(), 0xabcd);
        assert_eq!(h.tv_usec(), 0xdead_beef);
        assert_eq!(h.reply_micro(), 0x0102_0304);
        assert_eq!(h.window_size(), 1 << 20);
        assert_eq!(h.seq_nr(), 0x1234);
        assert_eq!(h.ack_nr(), 0x4321);
        assert_eq!(h.wire_version(), 1);
    }

    #[test]
    fn wire_version_rejects_garbage() {
        let mut b = [0u8; HEADER_SIZE];
        set_version_type(&mut b, 1, 9);
        assert_eq!(Header(&b).wire_version(), 0);
        set_version_type(&mut b, 1, ST_DATA);
        set_ext(&mut b, 3);
        assert_eq!(Header(&b).wire_version(), 0);
    }
}
