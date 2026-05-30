use std::collections::VecDeque;

use tokio::sync::{mpsc, Mutex};
use util::marshal::*;
use util::Buffer;

use crate::context::srtp::SrtpDecryptPending;
use crate::error::{Error, Result};

pub const SRTP_BUFFER_SIZE: usize = 1000 * 1000;
pub const SRTCP_BUFFER_SIZE: usize = 100 * 1000;

#[derive(Debug)]
pub struct Stream {
    ssrc: u32,
    tx: mpsc::Sender<u32>,
    pub(crate) buffer: Buffer,
    is_rtp: bool,
    pending_commits: Mutex<VecDeque<SrtpDecryptPending>>,
    commit_ctx: std::cell::UnsafeCell<Option<*mut crate::context::Context>>,
}

// SAFETY: commit_ctx is only accessed from the spawned task that owns
// both the Context and all Streams. No actual cross-thread access.
unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

impl Stream {
    pub fn new(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool) -> Self {
        Stream {
            ssrc, tx,
            buffer: Buffer::new(0, if is_rtp { SRTP_BUFFER_SIZE } else { SRTCP_BUFFER_SIZE }),
            is_rtp,
            pending_commits: Mutex::new(VecDeque::new()),
            commit_ctx: std::cell::UnsafeCell::new(None),
        }
    }

    pub fn with_buffer_size(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool, buffer_size: usize) -> Self {
        Stream {
            ssrc, tx,
            buffer: Buffer::new(0, buffer_size),
            is_rtp,
            pending_commits: Mutex::new(VecDeque::new()),
            commit_ctx: std::cell::UnsafeCell::new(None),
        }
    }

    pub unsafe fn set_commit_ctx(&self, ctx: *mut crate::context::Context) {
        *self.commit_ctx.get() = Some(ctx);
    }

    pub async fn queue_pending_commit(&self, pending: SrtpDecryptPending) {
        self.pending_commits.lock().await.push_back(pending);
    }

    async fn execute_pending_commit(&self) {
        if let Some(pending) = self.pending_commits.lock().await.pop_front() {
            let ctx_ptr = unsafe { *self.commit_ctx.get() };
            if let Some(ctx) = ctx_ptr {
                let ctx = unsafe { &mut *ctx };
                ctx.commit_srtp_decrypt(&pending);
            }
        }
    }

    pub fn get_ssrc(&self) -> u32 { self.ssrc }
    pub fn is_rtp_stream(&self) -> bool { self.is_rtp }
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.buffer.read(buf, None).await?;
        self.execute_pending_commit().await;
        Ok(n)
    }
    pub async fn read_rtp(&self, buf: &mut [u8]) -> Result<rtp::packet::Packet> {
        if !self.is_rtp { return Err(Error::InvalidRtpStream); }
        let n = self.buffer.read(buf, None).await?;
        let mut b = &buf[..n];
        let pkt = rtp::packet::Packet::unmarshal(&mut b)?;
        self.execute_pending_commit().await;
        Ok(pkt)
    }
    pub async fn read_rtcp(&self, buf: &mut [u8]) -> Result<Vec<Box<dyn rtcp::packet::Packet + Send + Sync>>> {
        if self.is_rtp { return Err(Error::InvalidRtcpStream); }
        let n = self.buffer.read(buf, None).await?;
        let mut b = &buf[..n];
        Ok(rtcp::packet::unmarshal(&mut b)?)
    }
    pub async fn close(&self) -> Result<()> {
        self.buffer.close().await;
        let _ = self.tx.send(self.ssrc).await;
        Ok(())
    }
}
