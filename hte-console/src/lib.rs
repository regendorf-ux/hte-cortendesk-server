//! hte-console (HTE Remote console, in Rust, step by step). Phase 0: shadow proxy, sanitiser, replay.
//! Phase 1: the device endpoints (heartbeat, sysinfo, audit, version) answered natively.
pub mod api;
pub mod audit;
pub mod config;
pub mod sqlite;
pub mod fixture;
pub mod laravel;
pub mod passwords;
pub mod php;
pub mod proxy;
pub mod replay;
pub mod sanitise;
pub mod seed;
pub mod strategy;
pub mod sync;
