use anyhow::{ensure, Result};
use zerocopy::{
    little_endian::{U32, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout,
};
use crate::hash::HASH_DATA_SIZE;
use crate::static_assert;

pub const IVFC_MAGIC: [u8; 4] = *b"IVFC";

/// IVFC level header. (HierarchicalIntegrityVerificationLevelInformation)
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct IvfcLevelHeader {
    pub logical_offset: U64,
    pub hash_data_size: U64,
    pub block_size: U32,
    pub _reserved: U32,
}

static_assert!(size_of::<IvfcLevelHeader>() == 0x18);

/// IVFC header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct IntegrityMetaInfo {
    pub magic: [u8; 4],
    pub version: U32,
    pub master_hash_size: U32,
    // start InfoLevelHash
    pub max_layers: U32,
    pub levels: [IvfcLevelHeader; 6],
    pub signature_salt: [u8; 0x20],
    // end InfoLevelHash
    pub master_hash: [u8; 0x20],
    pub _reserved: [u8; 0x18],
}

static_assert!(size_of::<IntegrityMetaInfo>() == HASH_DATA_SIZE);

impl IntegrityMetaInfo {
    pub fn verify(&self) -> Result<()> {
        ensure!(self.magic == IVFC_MAGIC, "Invalid IVFC magic: {:x?}", self.magic);
        Ok(())
    }
}
