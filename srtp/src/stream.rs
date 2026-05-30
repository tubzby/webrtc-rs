use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{mpsc, Mutex};
use util::marshal::*;
use util::Buffer;

use crate::error::{Error, Result};

pub const SRTP_BUFFER_SIZE: usize = 1000 * 1000;
pub const SRTCP_BUFFER_SIZE: usize = 100 * 1000;

static DIAG_MAX_GAP_US: AtomicU64 = AtomicU64::new(0);
static DIAG_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);
static DIAG_READ_SEQ: AtomicU64 = AtomicU64::new(0);
static DIAG_ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0);
static DIAG_READ_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn record_accept(_ssrc: u32, seq: u16) {
    DIAG_ACCEPT_COUNT.fetch_add(1, Ordering::Relaxed);
    DIAG_WRITE_SEQ.store(seq as u64, Ordering::Relaxed);
}

pub fn record_read(_ssrc: u32, seq: u16) {
    DIAG_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    DIAG_READ_SEQ.store(seq as u64, Ordering::Relaxed);
}

pub fn diag_snapshot() -> String {
    let accepts = DIAG_ACCEPT_COUNT.load(Ordering::Relaxed);
    let reads = DIAG_READ_COUNT.load(Ordering::Relaxed);
    let write_seq = DIAG_WRITE_SEQ.load(Ordering::Relaxed);
    let read_seq = DIAG_READ_SEQ.load(Ordering::Relaxed);
    let max_gap_ms = DIAG_MAX_GAP_US.load(Ordering::Relaxed) / 1000;
    format!("accepts={} reads={} write_seq={} read_seq={} max_gap={}ms",
        accepts, reads, write_seq, read_seq, max_gap_ms)
}

#[derive(Debug)]
pub struct Stream {
    ssrc: u32,
    tx: mpsc::Sender<u32>,
    pub(crate) buffer: Buffer,
    is_rtp: bool,
}

impl Stream {
    pub fn new(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool) -> Self {
        Stream { ssrc, tx, buffer: Buffer::new(0, if is_rtp { SRTP_BUFFER_SIZE } else { SRTCP_BUFFER_SIZE }), is_rtp }
    }
    pub fn with_buffer_size(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool, buffer_size: usize) -> Self {
        Stream { ssrc, tx, buffer: Buffer::new(0, buffer_size), is_rtp }
    }
    pub fn get_ssrc(&self) -> u32 { self.ssrc }
    pub fn is_rtp_stream(&self) -> bool { self.is_rtp }
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> { Ok(self.buffer.read(buf, None).await?) }
    pub async fn read_rtp(&self, buf: &mut [u8]) -> Result<rtp::packet::Packet> {
        if !self.is_rtp { return Err(Error::InvalidRtpStream); }
        let n = self.buffer.read(buf, None).await?;
        let mut b = &buf[..n];
        let pkt = rtp::packet::Packet::unmarshal(&mut b)?;
        record_read(self.ssrc, pkt.header.sequence_number);
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
