use super::*;

use std::{pin::Pin, task::Poll};

use ::tokio::io::{unix::AsyncFd, AsyncRead};
use futures_lite::{ready, FutureExt};

///References a single mmaped async ring buffer. Normally one per thread.
#[derive(Debug)]
pub struct AsyncRing {
    inner: Ring,
    waiter: AsyncWaiter,
}
impl AsyncRing {
    #[inline]
    pub(crate) fn init(
        socket: Socket,
        blocks: Vec<RawBlock>,
        opts: tpacket3::TpacketReq3,
    ) -> Result<Self> {
        let fd = socket.as_raw_fd();
        Ok(Self {
            inner: Ring::init(socket.clone(), blocks, opts)?,
            waiter: AsyncWaiter(AsyncFd::new(fd)?),
        })
    }

    ///Creates a new async ring buffer on the specified interface name and puts the interface into promiscuous mode
    #[inline]
    pub fn from_if_name(if_name: &str) -> Result<Self> {
        RingBuilder::new(if_name)?.build_async()
    }

    ///Creates a new async ring buffer from the supplied RingSettings struct
    #[inline]
    pub fn from_settings(settings: RingSettings) -> Result<Self> {
        RingBuilder::from_settings(settings)?.build_async()
    }

    ///Return inner socket
    #[inline]
    pub fn socket(&self) -> Socket {
        self.inner.socket()
    }

    ///Waits for a block to be added to the ring buffer and returns it
    pub async fn recv_block(&mut self) -> Result<Block<'_>> {
        loop {
            if let Some(block) = self.inner.check_current_block() {
                return Ok(block.into());
            }
            (&mut self.waiter).await?;
        }
    }

    ///Return a common blocks count in a ring buffer
    #[inline]
    pub fn blocks_count(&self) -> c_uint {
        self.inner.blocks_count()
    }

    ///Return a percentage of ready blocks in a ring buffer
    #[inline]
    pub fn buffer_saturation_threshold(&self, step_percent: u8) -> u8 {
        self.inner.buffer_saturation_threshold(step_percent)
    }
}

impl AsRawFd for AsyncRing {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[derive(Debug)]
struct AsyncWaiter(AsyncFd<RawFd>);
impl futures_lite::Future for AsyncWaiter {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let inner = &mut self.0;
        let mut guard = ready!(inner.poll_read_ready(cx))?;
        guard.clear_ready();
        Poll::Ready(Ok(()))
    }
}

///Packets stream
#[derive(Debug)]
pub struct Stream<'a> {
    inner: AsyncRing,
    cur_block: Option<RawPacketsConsumingIter<'a>>,
}
impl<'a> AsyncRead for Stream<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ::tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        loop {
            if self.cur_block.is_none() {
                if let Some(block) = self.inner.inner.check_current_block() {
                    self.cur_block = Some(Block::from(block).into_raw_packets_iter());
                }
            }
            if let Some(iter) = &mut self.cur_block {
                match iter.next() {
                    None => {
                        panic!("empty block");
                    }
                    Some(pack) => {
                        buf.put_slice(pack.payload());
                        if iter.is_last() {
                            // consume block on drop
                            self.cur_block.take();
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            ready!(self.inner.waiter.poll(cx))?;
        }
    }
}
