#![allow(dead_code)]

use std::{net::IpAddr, time::Duration};

#[derive(Debug, Clone)]
pub struct TorrentSummary {
    pub hash: String,
    pub name: String,
    pub total_seeders: u32,
    pub category: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub ip: IpAddr,
    pub port: u16,
    pub progress: f64,
    pub up_rate_bps: u64,
}

#[derive(Debug, Clone)]
pub struct BanDecision {
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub offence_number: u32,
    pub ttl: Duration,
    pub reason: String,
}
