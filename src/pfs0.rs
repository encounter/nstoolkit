use std::{
    ffi::CStr,
    io::{Read, Seek},
};

use anyhow::{ensure, Context, Result};
use zerocopy::{
    little_endian::{U32, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout,
};

use crate::{
    read::{read_box_slice, read_from, read_vec},
    static_assert,
};

pub const PFS0_MAGIC: [u8; 4] = *b"PFS0";

/// PFS0 header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct Pfs0Header {
    pub magic: [u8; 4],
    pub num_files: U32,
    pub string_table_size: U32,
    pub _reserved: U32,
}

static_assert!(size_of::<Pfs0Header>() == 0x10);

/// PFS0 file entry.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct Pfs0FileEntry {
    pub offset: U64,
    pub size: U64,
    pub string_table_offset: U32,
    pub _reserved: U32,
}

static_assert!(size_of::<Pfs0FileEntry>() == 0x18);

#[derive(Debug, Clone)]
pub struct Pfs0File {
    pub offset: u64,
    pub size: u64,
    pub name: String,
}

pub fn process_pfs0<R>(reader: &mut R) -> Result<Vec<Pfs0File>>
where R: Read + Seek + ?Sized {
    let header: Pfs0Header = read_from(reader)?;
    ensure!(header.magic == PFS0_MAGIC, "Invalid PFS0 magic: {:?}", header.magic);

    let entries: Vec<Pfs0FileEntry> =
        read_vec(reader, header.num_files.get() as usize).context("Failed to read PFS0 entries")?;
    let string_table: Box<[u8]> = read_box_slice(reader, header.string_table_size.get() as usize)
        .context("Failed to read PFS0 string table")?;
    let file_start = reader.stream_position().context("Failed to determine PFS0 file offset")?;
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        let offset = entry.string_table_offset.get() as usize;
        let c_str = CStr::from_bytes_until_nul(&string_table[offset..])
            .context("Failed to read PFS0 file name")?;
        let name = c_str.to_str().context("PFS0 filename is not valid UTF-8")?;
        files.push(Pfs0File {
            offset: file_start + entry.offset.get(),
            size: entry.size.get(),
            name: name.to_string(),
        });
    }
    Ok(files)
}
