use libc::{c_int, c_uint};

pub const TP_STATUS_KERNEL: u32 = 0;
pub const TP_STATUS_USER: u32 = 1;
//const TP_STATUS_COPY: u32 = 1 << 1;
//const TP_STATUS_LOSING: u32 = 1 << 2;
//const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;
//const TP_STATUS_CSUM_VALID: u32 = 1 << 7;

pub const TPACKET_V3: c_int = 2;

const TP_FT_REQ_FILL_RXHASH: c_uint = 1; //0x1;

pub const TP_BLK_STATUS_OFFSET: usize = 8;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketStatsV3 {
    pub tp_packets: c_uint,
    pub tp_drops: c_uint,
    pub tp_freeze_q_cnt: c_uint,
}

#[derive(Clone, Debug)]
#[repr(C)]
///Lower-level settings about ring buffer allocation and behavior
///tp_frame_size * tp_frame_nr must equal tp_block_size * tp_block_nr
pub struct TpacketReq3 {
    ///Block size of ring
    pub tp_block_size: c_uint,
    ///Number of blocks allocated for ring
    pub tp_block_nr: c_uint,
    ///Frame size of ring
    pub tp_frame_size: c_uint,
    ///Number of frames in ring
    pub tp_frame_nr: c_uint,
    ///Timeout in milliseconds
    pub tp_retire_blk_tov: c_uint,
    ///Offset to private data area
    pub tp_sizeof_priv: c_uint,
    ///Controls whether RXHASH is filled - 0 for false, 1 for true
    pub tp_feature_req_word: c_uint,
}
impl Default for TpacketReq3 {
    fn default() -> TpacketReq3 {
        TpacketReq3 {
            tp_block_size: 32768,
            tp_block_nr: 10000,
            tp_frame_size: 2048,
            tp_frame_nr: 160000,
            tp_retire_blk_tov: 100,
            tp_sizeof_priv: 0,
            tp_feature_req_word: TP_FT_REQ_FILL_RXHASH,
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketBlockDesc {
    pub version: u32,
    pub offset_to_priv: u32,
    pub hdr: TpacketBDHeader,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketBDHeader {
    pub block_status: u32,
    pub num_pkts: u32,
    pub offset_to_first_pkt: u32,
    pub blk_len: u32,
    pub seq_num: u64,
    pub ts_first_pkt: TpacketBDTS,
    pub ts_last_pkt: TpacketBDTS,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketBDTS {
    pub ts_sec: u32,
    pub ts_nsec: u32,
}

///Contains details about individual packets in a block
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Tpacket3Hdr {
    pub tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: TpacketHdrVariant1,
    _tp_padding: [u8; 8],
}

///Contains VLAN tags and RX Hash value (if enabled)
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketHdrVariant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    _tp_padding: u16,
}
