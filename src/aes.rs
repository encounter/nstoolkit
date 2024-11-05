use std::{
    io,
    io::{BufRead, Read, Seek},
};

use aes::{
    cipher::{
        block_padding::NoPadding, BlockDecryptMut, KeyInit, KeyIvInit, StreamCipher,
        StreamCipherSeek,
    },
    Aes128,
};

use crate::{array_ref, nca::NCA_SECTOR_SIZE};

/// Decrypts data in-place using AES-128-XTS with the given key.
pub fn aes_xts_decrypt(key: &[u8; 0x20], data: &mut [u8], sector_idx: u128) {
    let cipher_1 = Aes128::new(array_ref!(key, 0, 0x10).into());
    let cipher_2 = Aes128::new(array_ref!(key, 0x10, 0x10).into());
    let xts = <xts_mode::Xts128<Aes128>>::new(cipher_1, cipher_2);
    // Non-standard tweak: sector index is big-endian
    xts.decrypt_area(data, NCA_SECTOR_SIZE, sector_idx, |idx| idx.to_be_bytes());
}

/// Decrypts data in-place using AES-128-ECB with the given key.
pub fn aes_ecb_decrypt(key: &[u8; 0x10], data: &mut [u8]) {
    ecb::Decryptor::<Aes128>::new(key.into()).decrypt_padded_mut::<NoPadding>(data).unwrap();
}

pub trait Decryptor {
    fn decrypt_sector(&mut self, data: &mut [u8], cur_sector: u64);
}

pub struct AesXtsDecryptor {
    xts: xts_mode::Xts128<Aes128>,
}

impl AesXtsDecryptor {
    pub fn new(key: &[u8; 0x20]) -> Self {
        let cipher_1 = Aes128::new(array_ref!(key, 0, 0x10).into());
        let cipher_2 = Aes128::new(array_ref!(key, 0x10, 0x10).into());
        Self { xts: xts_mode::Xts128::new(cipher_1, cipher_2) }
    }
}

impl Decryptor for AesXtsDecryptor {
    fn decrypt_sector(&mut self, data: &mut [u8], cur_sector: u64) {
        // Non-standard tweak: sector index is big-endian
        self.xts.decrypt_sector(data, (cur_sector as u128).to_be_bytes());
    }
}

pub struct AesCtrDecryptor {
    ctr: ctr::Ctr64BE<Aes128>,
}

impl AesCtrDecryptor {
    pub fn new(key: &[u8; 0x10], nonce: &[u8; 0x10]) -> Self {
        Self { ctr: ctr::Ctr64BE::new(key.into(), nonce.into()) }
    }
}

impl Decryptor for AesCtrDecryptor {
    fn decrypt_sector(&mut self, data: &mut [u8], cur_sector: u64) {
        self.ctr.seek((cur_sector * NCA_SECTOR_SIZE as u64) as u128);
        self.ctr.apply_keystream(data);
    }
}

pub struct DecryptReader<R, D> {
    inner: R,
    decryptor: D,
    position: u64,
    sector_idx: u64,
    sector_buf: [u8; NCA_SECTOR_SIZE],
}

impl<R, D> DecryptReader<R, D> {
    pub fn new(inner: R, decryptor: D) -> Self {
        Self { inner, decryptor, position: 0, sector_idx: u64::MAX, sector_buf: [0u8; 0x200] }
    }
}

impl<R, D> Read for DecryptReader<R, D>
where
    R: Read + Seek,
    D: Decryptor,
{
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while !buf.is_empty() {
            let sector_buf = self.fill_buf()?;
            if sector_buf.is_empty() {
                break;
            }
            let len = buf.len().min(sector_buf.len());
            buf[..len].copy_from_slice(&sector_buf[..len]);
            buf = &mut buf[len..];
            self.position += len as u64;
            total += len;
        }
        Ok(total)
    }
}

impl<R, D> Seek for DecryptReader<R, D>
where
    R: Read + Seek,
    D: Decryptor,
{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.position = match pos {
            io::SeekFrom::Start(pos) => pos,
            io::SeekFrom::End(pos) => self.inner.seek(io::SeekFrom::End(pos))?,
            io::SeekFrom::Current(off) => self.position.saturating_add_signed(off),
        };
        Ok(self.position)
    }
}

impl<R, D> BufRead for DecryptReader<R, D>
where
    R: Read + Seek,
    D: Decryptor,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let cur_sector = self.position / NCA_SECTOR_SIZE as u64;
        if cur_sector != self.sector_idx {
            self.inner.seek(io::SeekFrom::Start(cur_sector * NCA_SECTOR_SIZE as u64))?;
            let mut read = 0;
            while read < self.sector_buf.len() {
                let len = self.inner.read(&mut self.sector_buf[read..])?;
                if len == 0 {
                    // Couldn't read a full sector, EOF
                    self.sector_idx = u64::MAX;
                    return Ok(&[]);
                }
                read += len;
            }
            self.decryptor.decrypt_sector(&mut self.sector_buf, cur_sector);
            self.sector_idx = cur_sector;
        }
        let sector_off = (self.position % NCA_SECTOR_SIZE as u64) as usize;
        Ok(&self.sector_buf[sector_off..])
    }

    fn consume(&mut self, amt: usize) { self.position += amt as u64; }
}
