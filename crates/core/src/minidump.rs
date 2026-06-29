//! Minimal native reader for user minidumps (`MDMP`).
//!
//! Replaces the previous `cdb` dependency for the PPL path: we parse the
//! full-memory user dump ourselves to (a) find a module's base address
//! (`ModuleListStream`) and (b) read process memory by virtual address
//! (`Memory64ListStream`). That's all we need to pull `s_guidOle32Secret`
//! and `g_pMTAEmptyCtx` out of a dumped PPL process without a debugger.

use anyhow::{anyhow, bail, Context, Result};

const MINIDUMP_SIGNATURE: u32 = 0x504d_444d; // 'MDMP'
const MODULE_LIST_STREAM: u32 = 4;
const MEMORY64_LIST_STREAM: u32 = 9;
const MINIDUMP_MODULE_SIZE: usize = 108;

fn rd_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("minidump: read u32 at {off} out of bounds"))
}

fn rd_u64(data: &[u8], off: usize) -> Result<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("minidump: read u64 at {off} out of bounds"))
}

/// A memory range present in the dump: virtual `start`, byte `size`, and the
/// `file_offset` where its bytes begin in the dump file.
struct Range {
    start: u64,
    size: u64,
    file_offset: u64,
}

pub struct MiniDump {
    data: Vec<u8>,
    /// (stream_type, rva, size)
    streams: Vec<(u32, usize, usize)>,
    ranges: Vec<Range>,
}

impl MiniDump {
    pub fn open(path: &str) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading dump '{path}'"))?;

        if rd_u32(&data, 0)? != MINIDUMP_SIGNATURE {
            bail!("'{path}' is not a minidump (missing MDMP signature)");
        }

        let num_streams = rd_u32(&data, 8)? as usize;
        let dir_rva = rd_u32(&data, 12)? as usize;

        let mut streams = Vec::with_capacity(num_streams);
        for i in 0..num_streams {
            let off = dir_rva + i * 12;
            let stype = rd_u32(&data, off)?;
            let dsize = rd_u32(&data, off + 4)? as usize;
            let rva = rd_u32(&data, off + 8)? as usize;
            streams.push((stype, rva, dsize));
        }

        let mut dump = MiniDump {
            data,
            streams,
            ranges: Vec::new(),
        };
        dump.parse_memory64()?;
        Ok(dump)
    }

    fn stream(&self, stream_type: u32) -> Option<(usize, usize)> {
        self.streams
            .iter()
            .find(|(t, _, _)| *t == stream_type)
            .map(|(_, rva, size)| (*rva, *size))
    }

    /// Parse `Memory64ListStream` into `self.ranges`.
    fn parse_memory64(&mut self) -> Result<()> {
        let (rva, _) = self
            .stream(MEMORY64_LIST_STREAM)
            .ok_or_else(|| anyhow!("dump has no Memory64List stream (not a full-memory dump?)"))?;

        let num_ranges = rd_u64(&self.data, rva)?;
        let base_rva = rd_u64(&self.data, rva + 8)?;

        let mut ranges = Vec::with_capacity(num_ranges as usize);
        let mut file_offset = base_rva;
        let mut p = rva + 16;
        for _ in 0..num_ranges {
            let start = rd_u64(&self.data, p)?;
            let size = rd_u64(&self.data, p + 8)?;
            ranges.push(Range {
                start,
                size,
                file_offset,
            });
            file_offset += size;
            p += 16;
        }
        self.ranges = ranges;
        Ok(())
    }

    /// Read `len` bytes of process memory at virtual address `va`.
    pub fn read(&self, va: u64, len: usize) -> Result<Vec<u8>> {
        for r in &self.ranges {
            if va >= r.start && (va - r.start) + len as u64 <= r.size {
                let off = (r.file_offset + (va - r.start)) as usize;
                return self
                    .data
                    .get(off..off + len)
                    .map(|b| b.to_vec())
                    .ok_or_else(|| anyhow!("dump range points past EOF at {off}"));
            }
        }
        Err(anyhow!("VA {va:#x} (+{len}) is not present in the dump"))
    }

    fn read_minidump_string(&self, rva: usize) -> Option<String> {
        let len = rd_u32(&self.data, rva).ok()? as usize; // length in bytes
        let start = rva + 4;
        let bytes = self.data.get(start..start + len)?;
        let utf16: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&utf16))
    }

    /// Base address of a loaded module (matched by file name, case-insensitive)
    /// from the `ModuleListStream`.
    pub fn module_base(&self, name: &str) -> Option<u64> {
        let (rva, _) = self.stream(MODULE_LIST_STREAM)?;
        let count = rd_u32(&self.data, rva).ok()?;
        let mut p = rva + 4;
        for _ in 0..count {
            let base = rd_u64(&self.data, p).ok()?;
            let name_rva = rd_u32(&self.data, p + 20).ok()? as usize; // ModuleNameRva @ +20
            if let Some(full) = self.read_minidump_string(name_rva) {
                let file = full
                    .rsplit(|c| c == '\\' || c == '/')
                    .next()
                    .unwrap_or(&full);
                if file.eq_ignore_ascii_case(name) {
                    return Some(base);
                }
            }
            p += MINIDUMP_MODULE_SIZE;
        }
        None
    }
}
