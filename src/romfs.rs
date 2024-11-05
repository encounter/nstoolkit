use std::io::{Read, Seek};

use anyhow::{ensure, Result};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zerocopy::little_endian::*;
use crate::{ivfc::IntegrityMetaInfo, read::read_from, static_assert};

/// RomFS header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct RomFsHeader {
    pub header_size: U64,
    pub dir_hash_table_offset: U64,
    pub dir_hash_table_size: U64,
    pub dir_meta_table_offset: U64,
    pub dir_meta_table_size: U64,
    pub file_hash_table_offset: U64,
    pub file_hash_table_size: U64,
    pub file_meta_table_offset: U64,
    pub file_meta_table_size: U64,
    pub data_offset: U64,
}

static_assert!(size_of::<RomFsHeader>() == 0x50);

pub fn process_romfs<R>(reader: &mut R) -> Result<()>
where R: Read + Seek + ?Sized {
    let header: RomFsHeader = read_from(reader)?;
    // println!("{:?}", header);
    ensure!(
        header.header_size.get() == size_of::<RomFsHeader>() as u64,
        "Invalid RomFS header size: {:#x}",
        header.header_size.get()
    );
    Ok(())
}
