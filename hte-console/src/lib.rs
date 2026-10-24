//! hte-console (HTE Remote console, in Rust, step by step). Phase 0: shadow proxy, sanitiser, replay.
//! Phase 1: the device endpoints (heartbeat, sysinfo, audit, version) answered natively.
//! Phase 2: the RustDesk client's sign-in (password, TOTP, OIDC) answered natively.
//! Phase 3: the server link (policy with HTE's scope, local addresses, refusals) and the scheduled sweeps.
pub mod api;
pub mod audit;
pub mod cache;
pub mod config;
pub mod fake_idp;
pub mod sqlite;
pub mod fixture;
pub mod laravel;
pub mod link;
pub mod oidc;
pub mod passwords;
pub mod passwords_sweep;
pub mod php;
pub mod proxy;
pub mod reach;
pub mod replay;
pub mod resolver;
pub mod sanitise;
pub mod seed;
pub mod signin;
pub mod snapshot;
pub mod strategy;
pub mod sweeps;
pub mod sync;
pub mod totp;
pub mod validate;
