use std::cell::UnsafeCell;
use std::collections::VecDeque;

use tokio::sync::{mpsc, Mutex};
use util::marshal::*;
use util::Buffer;

use crate::context::srtp::SrtpDecryptPending;
use crate::error::{Error, Result};

/// Limit the buffer size to 1MB
pub const SRTP_BUFFER_SIZE: usize = 1000 * 1000;

/// Limit the buffer size to 100KB
pub const SRTCP_BUFFER_SIZE: usize = 100 * 1000;

/// Stream handles decryption for a single RTP/RTCP SSRC
#[derive(Debug)]
pub struct Stream {
    ssrc: u32,
    tx: mpsc::Sender<u32>,
    pub(crate) buffer: Buffer,
    is_rtp: bool,
    /// Queue of pending replay commits. Each entry is executed after a
    /// successful buffer read, ensuring accept() only fires once the
    /// downstream reader has actually consumed the packet.
    pending_commits: Mutex<VecDeque<SrtpDecryptPending>>,
    /// Raw pointer to the Context for executing commits.
    /// Uses UnsafeCell since *mut T is not Send/Sync.
    /// Safe because the Context outlives the Stream (both owned by same task).
    commit_ctx: UnsafeCell<Option<*mut crate::context::Context>>,
}

// SAFETY: commit_ctx is only accessed from the spawned task that owns
// both the Context and all Streams. No actual cross-thread sharing occurs.
unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

impl Stream {
    /// Create a new stream
    pub fn new(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool) -> Self {
        Stream {
            ssrc,
            tx,
            buffer: Buffer::new(
                0,
                if is_rtp {
                    SRTP_BUFFER_SIZE
                } else {
                    SRTCP_BUFFER_SIZE
                },
            ),
            is_rtp,
            pending_commits: Mutex::new(VecDeque::new()),
            commit_ctx: UnsafeCell::new(None),
        }
    }

    /// Create a new stream with a custom buffer size in bytes.
    pub fn with_buffer_size(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool, buffer_size: usize) -> Self {
        Stream {
            ssrc,
            tx,
            buffer: Buffer::new(0, buffer_size),
            is_rtp,
            pending_commits: Mutex::new(VecDeque::new()),
            commit_ctx: UnsafeCell::new(None),
        }
    }

    /// Set the Context pointer for executing pending commits.
    /// # Safety
    /// The Context must outlive this Stream. This is guaranteed when both
    /// are owned by the same spawned task.
    pub unsafe fn set_commit_ctx(&self, ctx: *mut crate::context::Context) {
        *self.commit_ctx.get() = Some(ctx);
    }

    /// Queue a pending replay commit to execute after the next buffer read.
    pub async fn queue_pending_commit(&self, pending: SrtpDecryptPending) {
        self.pending_commits.lock().await.push_back(pending);
    }

    /// Execute the oldest pending commit, if any.
    async fn execute_pending_commit(&self) {
        eprintln!("SRTP EXECUTE_PENDING_COMMIT CALLED");
        if let Some(pending) = self.pending_commits.lock().await.pop_front() {
            // SAFETY: The Context outlives the Stream (same task ownership).
            let ctx_ptr = unsafe { *self.commit_ctx.get() };
            if let Some(ctx) = ctx_ptr {
                let ctx = unsafe { &mut *ctx };
                ctx.commit_srtp_decrypt(&pending);
            }
        }
    }

    /// GetSSRC returns the SSRC we are demuxing for
    pub fn get_ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Check if RTP is a stream.
    pub fn is_rtp_stream(&self) -> bool {
        self.is_rtp
    }

    /// Read reads and decrypts full RTP packet from the nextConn
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.buffer.read(buf, None).await?;
        self.execute_pending_commit().await;
        Ok(n)
    }

    /// ReadRTP reads and decrypts full RTP packet and its header from the nextConn
    pub async fn read_rtp(&self, buf: &mut [u8]) -> Result<rtp::packet::Packet> {
        if !self.is_rtp {
            return Err(Error::InvalidRtpStream);
        }

        let n = self.buffer.read(buf, None).await?;
        let mut b = &buf[..n];
        let pkt = rtp::packet::Packet::unmarshal(&mut b)?;

        // Execute pending commit now that the packet has been consumed.
        self.execute_pending_commit().await;

        Ok(pkt)
    }

    /// read_rtcp reads and decrypts full RTP packet and its header from the nextConn
    pub async fn read_rtcp(
        &self,
        buf: &mut [u8],
    ) -> Result<Vec<Box<dyn rtcp::packet::Packet + Send + Sync>>> {
        if self.is_rtp {
            return Err(Error::InvalidRtcpStream);
        }

        let n = self.buffer.read(buf, None).await?;
        let mut b = &buf[..n];
        let pkt = rtcp::packet::unmarshal(&mut b)?;

        // Execute pending commit.
        self.execute_pending_commit().await;

        Ok(pkt)
    }

    /// Close removes the ReadStream from the session and cleans up any associated state
    pub async fn close(&self) -> Result<()> {
        self.buffer.close().await;
        let _ = self.tx.send(self.ssrc).await;
        Ok(())
    }
}
