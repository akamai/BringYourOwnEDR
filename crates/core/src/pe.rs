//! Small helpers for locating sections inside on-disk system DLLs.
//!
//! The injection primitive repeatedly needs the `.data` section header of a
//! handful of `System32` DLLs (to compute scratch addresses inside the target).
//! Previously this 6-line `fs::read` + `parse` + `filter(.data)` block was
//! copy-pasted ~8 times per binary with a hard-coded `C:\windows` path. This
//! centralises it and honours `%SystemRoot%`.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use pe_parser::{pe::parse_portable_executable, section::SectionHeader};

/// Absolute path to a DLL inside the live `System32` directory.
pub fn system32_path(dll: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    PathBuf::from(root).join("System32").join(dll)
}

/// Read `System32\<dll>` from disk and return the header of its first
/// `.data` section.
pub fn system_dll_data_section(dll: &str) -> Result<SectionHeader> {
    let path = system32_path(dll);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed reading {} from disk", path.display()))?;

    let pe = parse_portable_executable(bytes.as_slice())
        .map_err(|e| anyhow!("failed parsing {}: {:?}", path.display(), e))?;

    pe.section_table
        .into_iter()
        .find(|section| section.name.starts_with(b".data"))
        .with_context(|| format!("no .data section found in {}", path.display()))
}
