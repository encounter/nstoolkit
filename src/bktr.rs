use anyhow::{ensure, Result};
use zerocopy::{
    little_endian::{U32, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout,
};

use crate::static_assert;

pub const BKTR_MAGIC: [u8; 4] = *b"BKTR";

/// BKTR header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct BktrHeader {
    pub offset: U64,
    pub size: U64,
    pub magic: [u8; 4],
    pub _0x14: U32,
    pub num_entries: U32,
    pub _0x1c: U32,
}

static_assert!(size_of::<BktrHeader>() == 0x20);

impl BktrHeader {
    pub fn verify(&self) -> Result<()> {
        ensure!(self.magic == BKTR_MAGIC, "Invalid BKTR magic: {:x?}", self.magic);
        Ok(())
    }
}
