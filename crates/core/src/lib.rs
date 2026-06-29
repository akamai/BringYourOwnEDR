//! PPLSystem core library.
//!
//! Shared building blocks for the two front-end binaries (`pplsystem.exe` and
//! `shellcode.exe`):
//!
//! * [`irundown`] - the IRundown `DoCallback` arbitrary-call primitive
//!   (James Forshaw's COM-remoting technique), the COM secret/context locator
//!   and the RPCSS/OXID table walker.
//! * [`kdmp`] / [`dmp`] - kernel live-dump creation and parsing (advanced
//!   PPL mode only).
//! * [`pe`] - small helpers for reading the `.data` section of system DLLs.

pub mod dmp;
pub mod irundown;
pub mod kdmp;
pub mod minidump;
pub mod pe;
