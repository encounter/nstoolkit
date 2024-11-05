use std::{
    io,
    io::{BufRead, Read, Seek, SeekFrom},
};

use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use zerocopy::{little_endian::*, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::{read::read_box_slice, static_assert};

pub const HASH_DATA_SIZE: usize = 0xF8;

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct HierarchicalSha256Data {
    pub master_hash: [u8; 0x20],
    pub block_size: U32,
    pub layer_count: U32,
    pub layer_regions: [LayerRegion; 5],
    pub _reserved: [u8; 0x80],
}

static_assert!(size_of::<HierarchicalSha256Data>() == HASH_DATA_SIZE);

impl HierarchicalSha256Data {
    pub fn verify(&self) -> Result<()> {
        ensure!(
            self.layer_count.get() == 2,
            "Invalid HierarchicalSha256Data layer_count: {}",
            self.layer_count.get()
        );
        let hash_layer = &self.layer_regions[0];
        ensure!(
            hash_layer.size.get() % 0x20 == 0,
            "Invalid HierarchicalSha256Data hash region size: {:#x}",
            hash_layer.size.get()
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct LayerRegion {
    pub offset: U64,
    pub size: U64,
}

pub struct HierarchicalSha256Reader<R> {
    inner: R,
    header: HierarchicalSha256Data,
    hash_table: Box<[[u8; 0x20]]>,
    block_idx: u32,
    block: Box<[u8]>,
    position: u64,
}

impl<R> HierarchicalSha256Reader<R>
where R: Read + Seek
{
    pub fn new(mut reader: R, header: &HierarchicalSha256Data) -> io::Result<Self> {
        header.verify().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let hash_layer = &header.layer_regions[0];
        reader.seek(SeekFrom::Start(hash_layer.offset.get()))?;
        let hash_table =
            read_box_slice::<[u8; 0x20], _>(&mut reader, hash_layer.size.get() as usize / 0x20)?;
        let digest: [u8; 0x20] = Sha256::digest(hash_table.as_bytes()).into();
        if digest != header.master_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Master hash verification failed",
            ));
        }
        let block = <[u8]>::new_box_zeroed_with_elems(header.block_size.get() as usize)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        Ok(Self {
            inner: reader,
            header: header.clone(),
            hash_table,
            block_idx: u32::MAX,
            block,
            position: 0,
        })
    }
}

impl<R> Read for HierarchicalSha256Reader<R>
where R: Read + Seek
{
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while !buf.is_empty() {
            let block = self.fill_buf()?;
            if block.is_empty() {
                break;
            }
            let len = buf.len().min(block.len());
            buf[..len].copy_from_slice(&block[..len]);
            buf = &mut buf[len..];
            self.position += len as u64;
            total += len;
        }
        Ok(total)
    }
}

impl<R> BufRead for HierarchicalSha256Reader<R>
where R: Read + Seek
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let data_layer = &self.header.layer_regions[1];
        if self.position >= data_layer.size.get() {
            return Ok(&[]);
        }

        let block_size = self.header.block_size.get() as u64;
        let block_offset = (self.position % block_size) as usize;
        let current_block = (self.position / block_size) as u32;
        let current_block_start = current_block as u64 * block_size;
        let current_block_size = ((current_block_start + block_size).min(data_layer.size.get())
            - current_block_start) as usize;

        // Read new block if necessary
        if current_block != self.block_idx {
            self.inner.seek(SeekFrom::Start(data_layer.offset.get() + current_block_start))?;
            let mut read = 0;
            while read < current_block_size {
                let len = self.inner.read(&mut self.block[read..current_block_size])?;
                if len == 0 {
                    break;
                }
                read += len;
            }
            // Verify block hash if available
            if let Some(block_hash) = self.hash_table.get(current_block as usize) {
                // println!("Verifying block {}/{}", current_block + 1, self.hash_table.len());
                let digest: [u8; 0x20] = Sha256::digest(&self.block[..read]).into();
                if digest != *block_hash {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Block {}/{} verification failed",
                            current_block + 1,
                            self.hash_table.len()
                        ),
                    ));
                }
            }
            self.block_idx = current_block;
        }

        Ok(&self.block[block_offset..current_block_size])
    }

    fn consume(&mut self, amt: usize) { self.position += amt as u64; }
}

impl<R> Seek for HierarchicalSha256Reader<R>
where R: Read + Seek
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let data_layer = &self.header.layer_regions[1];
        self.position = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => data_layer.size.get().saturating_add_signed(p),
            SeekFrom::Current(p) => self.position.saturating_add_signed(p),
        };
        Ok(self.position)
    }
}
