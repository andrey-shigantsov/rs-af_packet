use std;
use std::io::{Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;

use libc::{
    bind, c_int, c_uint, c_void, getpid, mmap, poll, pollfd, sockaddr, sockaddr_ll,
    sockaddr_storage, AF_PACKET, ETH_P_ALL, MAP_LOCKED, MAP_NORESERVE, MAP_SHARED, POLLERR, POLLIN,
    PROT_READ, PROT_WRITE,
};

use crate::socket::{self, Socket, IFF_PROMISC};

use crate::tpacket3;

#[cfg(feature = "async-tokio")]
mod r#async;
#[cfg(feature = "async-tokio")]
pub use r#async::tokio::AsyncRing;

//Used digits for these consts, if they were defined differently in C headers I have added that definition in the comments beside them

const PACKET_RX_RING: c_int = 5;
const PACKET_STATISTICS: c_int = 6;
const PACKET_VERSION: c_int = 10;
const PACKET_FANOUT: c_int = 18;

/* https://stackoverflow.com/questions/43193889/sending-data-with-packet-mmap-and-packet-tx-ring-is-slower-than-normal-withou */

pub const PACKET_FANOUT_HASH: c_int = 0;
pub const PACKET_FANOUT_LB: c_int = 1;
pub const PACKET_FANOUT_CPU: c_int = 2;

///Settings to be used to bring up each ring
#[derive(Clone, Debug)]
pub struct RingSettings {
    ///Interface name
    pub if_name: String,
    ///PACKET_FANOUT_HASH will pin flows to individual threads, PACKET_FANOUT_LB will distribute
    ///them across multiple threads
    pub fanout_method: c_int,
    ///Lower-level settings including block size, also enable/disable filling RXHASH in packet data
    pub ring_settings: tpacket3::TpacketReq3,
    ///Filter program
    pub bpf: Option<socket::FilterProgram>,
}

impl Default for RingSettings {
    fn default() -> RingSettings {
        RingSettings {
            if_name: String::from("eth0"),
            fanout_method: PACKET_FANOUT_HASH,
            ring_settings: tpacket3::TpacketReq3::default(),
            bpf: None,
        }
    }
}

///Builder for a `Ring`.
pub struct RingBuilder {
    socket: Socket,
    promiscuous: bool,
    fanout_method: i32,
    opts: tpacket3::TpacketReq3,
    bpf: Option<socket::FilterProgram>,
}
impl RingBuilder {
    pub fn new(if_name: &str) -> Result<Self> {
        Ok(Self {
            socket: Socket::from_if_name(if_name, socket::AF_PACKET)?,
            promiscuous: true,
            fanout_method: PACKET_FANOUT_HASH,
            opts: tpacket3::TpacketReq3::default(),
            bpf: None,
        })
    }

    pub fn from_settings(settings: RingSettings) -> Result<Self> {
        Ok(Self {
            socket: Socket::from_if_name(&settings.if_name, socket::AF_PACKET)?,
            promiscuous: true,
            fanout_method: settings.fanout_method,
            opts: settings.ring_settings,
            bpf: settings.bpf,
        })
    }

    pub fn promiscuous(mut self, flag: bool) -> Self {
        self.promiscuous = flag;
        self
    }

    pub fn fanout_method(mut self, method: i32) -> Self {
        self.fanout_method = method;
        self
    }

    pub fn block_size(mut self, size: u32) -> Self {
        self.opts.tp_block_size = size;
        self
    }

    pub fn block_count(mut self, count: u32) -> Self {
        self.opts.tp_block_nr = count;
        self
    }

    pub fn frame_size(mut self, size: u32) -> Self {
        self.opts.tp_frame_size = size;
        self
    }

    pub fn timeout(mut self, ms: u32) -> Self {
        self.opts.tp_retire_blk_tov = ms;
        self
    }

    pub fn filter(mut self, program: socket::FilterProgram) -> Self {
        self.bpf = Some(program);
        self
    }

    fn prepare_socket(&mut self, non_blocking: bool) -> Result<Vec<RawBlock>> {
        if non_blocking {
            self.socket.set_non_blocking()?;
        }

        if self.promiscuous {
            self.socket.set_flag(IFF_PROMISC as u64)?;
        }

        self.opts.tp_frame_nr =
            (self.opts.tp_block_size * self.opts.tp_block_nr) / self.opts.tp_frame_size;
        self.socket
            .setsockopt(PACKET_VERSION, tpacket3::TPACKET_V3)?;
        self.socket.setsockopt(PACKET_RX_RING, self.opts.clone())?;

        let mmap = self.mmap()?;
        let mut blocks = Vec::new();
        unsafe {
            for idx in 0..self.opts.tp_block_nr {
                let raw_data = mmap.offset(idx as isize * self.opts.tp_block_size as isize);
                blocks.push(RawBlock {
                    desc: std::mem::transmute(raw_data),
                    raw_data,
                })
            }
        }
        drop(mmap);

        self.bind()?;

        let fanout = (unsafe { getpid() } & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
        self.socket.setsockopt(PACKET_FANOUT, fanout)?;

        if let Some(program) = self.bpf.take() {
            self.socket.set_bpf_filter(program)?;
        }

        Ok(blocks)
    }

    pub fn build(mut self) -> Result<Ring> {
        let blocks = self.prepare_socket(false)?;
        Ok(Ring::init(self.socket, blocks, self.opts)?)
    }

    #[cfg(feature = "async-tokio")]
    pub fn build_async(mut self) -> Result<AsyncRing> {
        let blocks = self.prepare_socket(true)?;
        Ok(AsyncRing::init(self.socket, blocks, self.opts)?)
    }

    fn mmap(&mut self) -> Result<*mut u8> {
        match unsafe {
            mmap(
                std::ptr::null_mut(),
                (self.opts.tp_block_size * self.opts.tp_block_nr) as usize,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_LOCKED | MAP_NORESERVE,
                self.socket.fd,
                0,
            )
        } as isize
        {
            -1 => Err(Error::last_os_error()),
            map => Ok(map as *mut u8),
        }
    }

    fn bind(&mut self) -> Result<()> {
        unsafe {
            let mut ss: sockaddr_storage = std::mem::zeroed();
            let sll: *mut sockaddr_ll = &mut ss as *mut sockaddr_storage as *mut sockaddr_ll;
            (*sll).sll_family = AF_PACKET as u16;
            (*sll).sll_protocol = (ETH_P_ALL as u16).to_be();
            (*sll).sll_ifindex = self.socket.if_index as c_int;

            let sa = (&ss as *const sockaddr_storage) as *const sockaddr;
            let res = bind(
                self.socket.fd,
                sa,
                std::mem::size_of::<sockaddr_ll>() as u32,
            );
            if res == -1 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    }
}

///References a single mmaped ring buffer. Normally one per thread.
#[derive(Debug)]
pub struct Ring {
    socket: Socket,
    blocks: Vec<RawBlock>,
    opts: tpacket3::TpacketReq3,
    cur_idx: u32,
}

impl Ring {
    #[inline]
    pub(crate) fn init(
        socket: Socket,
        blocks: Vec<RawBlock>,
        opts: tpacket3::TpacketReq3,
    ) -> Result<Self> {
        Ok(Self {
            socket,
            blocks,
            opts,
            cur_idx: 0,
        })
    }

    ///Creates a new ring buffer on the specified interface name and puts the interface into promiscuous mode
    #[inline]
    pub fn from_if_name(if_name: &str) -> Result<Self> {
        RingBuilder::new(if_name)?.build()
    }

    ///Creates a new ring buffer from the supplied RingSettings struct
    #[inline]
    pub fn from_settings(settings: RingSettings) -> Result<Self> {
        RingBuilder::from_settings(settings)?.build()
    }

    ///Return inner socket
    #[inline]
    pub fn socket(&self) -> Socket {
        self.socket.clone()
    }

    ///Waits for a block to be added to the ring buffer and returns it
    #[inline]
    pub fn recv_block<'a>(&mut self) -> Block<'a> {
        loop {
            // Check block ready before wait for performance
            if let Some(block) = self.check_current_block() {
                return block.into();
            }
            self.wait_for_block();
        }
    }

    ///Return a common blocks count in a ring buffer
    #[inline]
    pub fn blocks_count(&self) -> c_uint {
        self.opts.tp_block_nr
    }

    ///Return a percentage of ready blocks in a ring buffer
    #[inline]
    pub fn buffer_saturation_threshold(&self, step_percent: u8) -> u8 {
        assert!(step_percent < 50);
        let step = {
            let step = (self.opts.tp_block_nr as u64 * step_percent as u64 / 100) as u32;
            if step == 0 {
                1
            } else {
                step
            }
        };

        let mut n = 0;

        let mut idx = self.cur_idx + step;
        idx %= self.opts.tp_block_nr;
        while n < self.opts.tp_block_nr {
            n += step;
            if n > self.opts.tp_block_nr {
                n = self.opts.tp_block_nr;
            }
            if self.blocks.get(idx as usize).unwrap().is_ready() {
                idx += step;
                idx %= self.opts.tp_block_nr;
            } else {
                break;
            }
        }
        (n * 100 / self.opts.tp_block_nr) as u8
    }

    #[inline]
    fn wait_for_block(&self) {
        let mut pfd = pollfd {
            fd: self.socket.fd,
            events: POLLIN | POLLERR,
            revents: 0,
        };

        unsafe {
            poll(&mut pfd, 1, -1);
        }
    }

    //check all blocks in memory space
    #[inline]
    pub(crate) fn check_current_block<'a>(&mut self) -> Option<&mut RawBlock> {
        let block = &mut self.blocks[self.cur_idx as usize];
        if block.is_ready() {
            self.cur_idx += 1;
            self.cur_idx %= self.opts.tp_block_nr;
            Some(block)
        } else {
            None
        }
    }
}

unsafe impl Send for Ring {}
impl AsRawFd for Ring {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RawBlock {
    desc: *mut tpacket3::TpacketBlockDesc,
    raw_data: *mut u8,
}
impl RawBlock {
    #[inline]
    pub(crate) fn desc(&self) -> &tpacket3::TpacketBlockDesc {
        unsafe { self.desc.as_ref().unwrap() }
    }

    #[inline]
    pub(crate) fn _desc_mut(&mut self) -> &mut tpacket3::TpacketBlockDesc {
        unsafe { self.desc.as_mut().unwrap() }
    }

    #[inline]
    pub(crate) fn is_ready(&self) -> bool {
        (self.desc().hdr.block_status & tpacket3::TP_STATUS_USER) != 0
    }
}

///Contains a reference to a block as it exists in the ring buffer, its block descriptor.
#[derive(Debug)]
pub struct Block<'a> {
    desc: Pin<&'a mut tpacket3::TpacketBlockDesc>,
    raw_data: Pin<&'a mut [u8]>,
}
impl<'a> Block<'a> {
    #[inline]
    pub fn desc(&self) -> &tpacket3::TpacketBlockDesc {
        &self.desc
    }

    #[inline]
    pub fn desc_mut(&mut self) -> &mut tpacket3::TpacketBlockDesc {
        &mut self.desc
    }

    ///Marks a block as consumed to be destroyed by the kernel
    #[inline]
    pub fn consume(&mut self) {
        self.desc_mut().hdr.block_status = tpacket3::TP_STATUS_KERNEL;
    }

    ///Returns a `Vec` of details and references to raw packets that can be read from the ring buffer
    #[inline]
    pub fn get_raw_packets(&self) -> Vec<RawPacket> {
        self.raw_packets_iter().collect()
    }

    ///Returns a raw packets iterator
    pub fn raw_packets_iter(&self) -> RawPacketIter<'a> {
        RawPacketIter {
            raw_data: Pin::new(unsafe {
                let ptr = self.raw_data.as_ptr();
                std::slice::from_raw_parts(ptr, self.raw_data.len())
            }),
            next_offset: self.desc.hdr.offset_to_first_pkt as usize,
            count: self.desc.hdr.num_pkts,
            cur_idx: 0,
            cur_next_offset: None,
        }
    }

    ///Convert block into raw packets iterator with consume on drop
    pub fn into_raw_packets_iter(mut self) -> RawPacketsConsumingIter<'a> {
        RawPacketsConsumingIter(
            RawPacketIter {
                raw_data: Pin::new(unsafe {
                    let ptr = self.raw_data.as_mut_ptr();
                    std::slice::from_raw_parts_mut(ptr, self.raw_data.len())
                }),
                next_offset: self.desc.hdr.offset_to_first_pkt as usize,
                count: self.desc.hdr.num_pkts,
                cur_idx: 0,
                cur_next_offset: None,
            },
            self,
        )
    }
}

impl<'a> From<&mut RawBlock> for Block<'a> {
    fn from(block: &mut RawBlock) -> Self {
        Self {
            desc: Pin::new(unsafe { block.desc.as_mut().unwrap() }),
            raw_data: Pin::new(unsafe {
                std::slice::from_raw_parts_mut(block.raw_data, block.desc().hdr.blk_len as usize)
            }),
        }
    }
}

///Raw packets iterator for a block.
#[derive(Debug)]
pub struct RawPacketIter<'a> {
    raw_data: Pin<&'a [u8]>,

    next_offset: usize,
    cur_next_offset: Option<usize>,
    cur_idx: u32,
    count: u32,
}
impl<'a> RawPacketIter<'a> {
    pub fn is_last(&self) -> bool {
        self.cur_idx == self.count
    }
    pub(crate) fn current(&mut self) -> Option<RawPacket<'a>> {
        if self.cur_idx >= self.count {
            return None;
        }
        assert_ne!(self.next_offset, 0);
        assert_ne!(self.next_offset, self.raw_data.len());

        let offset = self.next_offset;
        assert!(offset <= i32::MAX as usize);

        let header = unsafe {
            std::mem::transmute::<_, *const tpacket3::Tpacket3Hdr>(
                (self.raw_data.map_unchecked(|buf| &buf[offset..])).as_ptr(),
            )
            .as_ref()
            .unwrap()
        };

        let next_offset = if self.cur_idx < self.count - 1 {
            offset + header.tp_next_offset as usize
        } else {
            self.raw_data.len()
        };
        self.cur_next_offset = Some(next_offset);

        let payload_offset = offset + header.tp_mac as usize;
        assert!(payload_offset <= i32::MAX as usize);
        Some(RawPacket {
            header: Pin::new(header),
            payload: unsafe { self.raw_data.map_unchecked(|buf| &buf[payload_offset..]) },
        })
    }
    pub(crate) fn flush_current(&mut self) -> Option<()> {
        if let Some(next_offset) = self.cur_next_offset.take() {
            self.next_offset = next_offset;
            self.cur_idx += 1;
            Some(())
        } else {
            None
        }
    }
}

impl<'a> Iterator for RawPacketIter<'a> {
    type Item = RawPacket<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(res) = self.current() {
            self.flush_current();
            Some(res)
        } else {
            None
        }
    }
}

///Raw packets iterator for a block with consume a block on drop.
#[derive(Debug)]
pub struct RawPacketsConsumingIter<'a>(RawPacketIter<'a>, Block<'a>);
impl<'a> RawPacketsConsumingIter<'a> {
    pub fn is_last(&self) -> bool {
        self.0.is_last()
    }
}
impl<'a> Iterator for RawPacketsConsumingIter<'a> {
    type Item = RawPacket<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
impl<'a> Drop for RawPacketsConsumingIter<'a> {
    fn drop(&mut self) {
        self.1.consume()
    }
}

///Contains a reference to an individual packet in a block, as well as details about that packet
#[derive(Debug)]
pub struct RawPacket<'a> {
    ///Contains packet details
    header: Pin<&'a tpacket3::Tpacket3Hdr>,
    ///Raw packet payload
    payload: Pin<&'a [u8]>,
}
impl<'a> RawPacket<'a> {
    pub fn header(&self) -> &'a tpacket3::Tpacket3Hdr {
        unsafe { self.header.map_unchecked(|hdr| hdr).get_ref() }
    }
    pub fn payload(&self) -> &'a [u8] {
        unsafe { self.payload.map_unchecked(|buf| buf).get_ref() }
    }
}

///This is very easy because the Linux kernel has its own counters that are reset every time
///getsockopt() is called
#[inline]
pub fn get_rx_statistics(fd: i32) -> Result<tpacket3::TpacketStatsV3> {
    let mut optval = tpacket3::TpacketStatsV3 {
        tp_packets: 0,
        tp_drops: 0,
        tp_freeze_q_cnt: 0,
    };
    socket::get_sock_opt(
        fd,
        PACKET_STATISTICS,
        &(&mut optval as *mut _ as *mut c_void),
    )?;
    Ok(optval)
}
