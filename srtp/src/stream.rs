use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::{mpsc, Mutex};
use util::marshal::*;
use util::Buffer;

use crate::error::{Error, Result};

pub const SRTP_BUFFER_SIZE: usize = 1000 * 1000;
pub const SRTCP_BUFFER_SIZE: usize = 100 * 1000;

static DIAG_SSRC: AtomicU64 = AtomicU64::new(0);
static DIAG_WRITE_US: AtomicU64 = AtomicU64::new(0);
static DIAG_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);
static DIAG_READ_US: AtomicU64 = AtomicU64::new(0);
static DIAG_READ_SEQ: AtomicU64 = AtomicU64::new(0);
static DIAG_MAX_GAP_US: AtomicU64 = AtomicU64::new(0);
static DIAG_NACK_COUNT: AtomicU64 = AtomicU64::new(0);
static DIAG_LAST_LOG_SEQ: AtomicU64 = AtomicU64::new(0);
static DIAG_STALL_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn record_accept(ssrc: u32, seq: u16) {
    let now = Instant::now().elapsed().as_micros() as u64;
    DIAG_SSRC.store(ssrc as u64, Ordering::Relaxed);
    DIAG_WRITE_US.store(now, Ordering::Relaxed);
    DIAG_WRITE_SEQ.store(seq as u64, Ordering::Relaxed);
}

pub fn record_read(ssrc: u32, seq: u16) {
    let now = Instant::now().elapsed().as_micros() as u64;
    let write_us = DIAG_WRITE_US.load(Ordering::Relaxed);
    let write_seq = DIAG_WRITE_SEQ.load(Ordering::Relaxed);
    DIAG_READ_US.store(now, Ordering::Relaxed);
    DIAG_READ_SEQ.store(seq as u64, Ordering::Relaxed);
    let gap_us = now.saturating_sub(write_us);
    let max_gap = DIAG_MAX_GAP_US.load(Ordering::Relaxed);
    if gap_us > max_gap { DIAG_MAX_GAP_US.store(gap_us, Ordering::Relaxed); }
    let read_seq = DIAG_READ_SEQ.load(Ordering::Relaxed);
    let last_log = DIAG_LAST_LOG_SEQ.load(Ordering::Relaxed);
    if read_seq >= last_log + 200 {
        if DIAG_LAST_LOG_SEQ.compare_exchange(last_log, read_seq, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            eprintln!("SRTP DIAG ssrc={} read_seq={} write_seq={} max_gap={}ms nacks={} stalls={}",
                ssrc, read_seq, write_seq, DIAG_MAX_GAP_US.load(Ordering::Relaxed)/1000,
                DIAG_NACK_COUNT.load(Ordering::Relaxed), DIAG_STALL_COUNT.load(Ordering::Relaxed));
        }
    }
    if gap_us > 10000 {
        eprintln!("SRTP GAP ssrc={} seq={} gap={}ms", ssrc, seq, gap_us/1000);
    }
}

pub fn record_nack(ssrc: u32, missing_start: u16) {
    let now = Instant::now().elapsed().as_micros() as u64;
    let write_us = DIAG_WRITE_US.load(Ordering::Relaxed);
    let gap_us = now.saturating_sub(write_us);
    DIAG_NACK_COUNT.fetch_add(1, Ordering::Relaxed);
    if gap_us < 5000 {
        eprintln!("SRTP NACK EARLY ssrc={} missing={} gap={}ms", ssrc, missing_start, gap_us/1000);
    }
    let read_seq = DIAG_READ_SEQ.load(Ordering::Relaxed);
    if (missing_start as i64).wrapping_sub(read_seq as i64) > 0 {
        DIAG_STALL_COUNT.fetch_add(1, Ordering::Relaxed);
    }
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
