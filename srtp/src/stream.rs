use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::time::Instant;

use tokio::sync::{mpsc, Mutex};
use util::marshal::*;
use util::Buffer;

use crate::error::{Error, Result};

pub const SRTP_BUFFER_SIZE: usize = 1000 * 1000;
pub const SRTCP_BUFFER_SIZE: usize = 100 * 1000;

/// Diagnostic: track write-read latency per SSRC
static DIAG_MAX_LATENCY_US: AtomicU64 = AtomicU64::new(0);
static DIAG_MIN_LATENCY_US: AtomicU64 = AtomicU64::new(u64::MAX);
static DIAG_TOTAL_LATENCY_US: AtomicU64 = AtomicU64::new(0);
static DIAG_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static DIAG_LAST_WRITE_TIMESTAMP_US: AtomicI64 = AtomicI64::new(-1);
static DIAG_LAST_LOG: AtomicU64 = AtomicU64::new(0);

/// Stream handles decryption for a single RTP/RTCP SSRC
#[derive(Debug)]
pub struct Stream {
    ssrc: u32,
    tx: mpsc::Sender<u32>,
    pub(crate) buffer: Buffer,
    is_rtp: bool,
}

impl Stream {
    pub fn new(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool) -> Self {
        Stream {
            ssrc, tx,
            buffer: Buffer::new(0, if is_rtp { SRTP_BUFFER_SIZE } else { SRTCP_BUFFER_SIZE }),
            is_rtp,
        }
    }

    pub fn with_buffer_size(ssrc: u32, tx: mpsc::Sender<u32>, is_rtp: bool, buffer_size: usize) -> Self {
        Stream { ssrc, tx, buffer: Buffer::new(0, buffer_size), is_rtp }
    }

    pub fn get_ssrc(&self) -> u32 { self.ssrc }
    pub fn is_rtp_stream(&self) -> bool { self.is_rtp }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let now_us = Instant::now().elapsed().as_micros() as u64;
        let last_write = DIAG_LAST_WRITE_TIMESTAMP_US.load(Ordering::Relaxed);
        if last_write >= 0 {
            let latency = now_us.saturating_sub(last_write as u64);
            DIAG_MAX_LATENCY_US.fetch_max(latency, Ordering::Relaxed);
            DIAG_MIN_LATENCY_US.fetch_min(latency, Ordering::Relaxed);
            DIAG_TOTAL_LATENCY_US.fetch_add(latency, Ordering::Relaxed);
            let count = DIAG_READ_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            let last_log = DIAG_LAST_LOG.load(Ordering::Relaxed);
            if count >= last_log + 500 {
                if DIAG_LAST_LOG.compare_exchange(last_log, count, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    let avg = DIAG_TOTAL_LATENCY_US.load(Ordering::Relaxed) / count;
                    let max = DIAG_MAX_LATENCY_US.load(Ordering::Relaxed);
                    let min = DIAG_MIN_LATENCY_US.load(Ordering::Relaxed);
                    eprintln!("SRTP DIAG ssrc={} reads={} min={}us avg={}us max={}us",
                        self.ssrc, count, min, avg, max);
                }
            }
        }
        let n = self.buffer.read(buf, None).await?;
        Ok(n)
    }

    pub async fn read_rtp(&self, buf: &mut [u8]) -> Result<rtp::packet::Packet> {
        if !self.is_rtp { return Err(Error::InvalidRtpStream); }
        let now_us = Instant::now().elapsed().as_micros() as u64;
        let last_write = DIAG_LAST_WRITE_TIMESTAMP_US.load(Ordering::Relaxed);
        if last_write >= 0 {
            let latency = now_us.saturating_sub(last_write as u64);
            DIAG_MAX_LATENCY_US.fetch_max(latency, Ordering::Relaxed);
            DIAG_MIN_LATENCY_US.fetch_min(latency, Ordering::Relaxed);
            DIAG_TOTAL_LATENCY_US.fetch_add(latency, Ordering::Relaxed);
            let count = DIAG_READ_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            let last_log = DIAG_LAST_LOG.load(Ordering::Relaxed);
            if count >= last_log + 500 {
                if DIAG_LAST_LOG.compare_exchange(last_log, count, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    let avg = DIAG_TOTAL_LATENCY_US.load(Ordering::Relaxed) / count;
                    let max = DIAG_MAX_LATENCY_US.load(Ordering::Relaxed);
                    let min = DIAG_MIN_LATENCY_US.load(Ordering::Relaxed);
                    eprintln!("SRTP DIAG ssrc={} reads={} min={}us avg={}us max={}us",
                        self.ssrc, count, min, avg, max);
                }
            }
        }
        let n = self.buffer.read(buf, None).await?;
        let mut b = &buf[..n];
        Ok(rtp::packet::Packet::unmarshal(&mut b)?)
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

/// Called by session after buffer.write() to record the timestamp
pub fn record_write_timestamp() {
    let now_us = Instant::now().elapsed().as_micros() as i64;
    DIAG_LAST_WRITE_TIMESTAMP_US.store(now_us, Ordering::Relaxed);
}
