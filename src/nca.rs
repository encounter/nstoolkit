use std::{
    fmt::{Display, Formatter},
    io::{Read, Seek},
};

use anyhow::{bail, ensure, Context, Result};
use rsa::{
    pss::{Signature, VerifyingKey},
    signature::Verifier,
    BigUint, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use zerocopy::{
    little_endian::{U16, U32, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout,
};

use crate::{
    aes::{aes_ecb_decrypt, aes_xts_decrypt, AesCtrDecryptor, AesXtsDecryptor, DecryptReader},
    array_ref_mut,
    bktr::BktrHeader,
    hash::{HierarchicalSha256Data, HierarchicalSha256Reader, HASH_DATA_SIZE},
    ivfc::IntegrityMetaInfo,
    keys::{KeySet, NCA_KEYS_RETAIL},
    pfs0::process_pfs0,
    read::{read_from, Reader},
    romfs::process_romfs,
    static_assert,
    util::WindowedReader,
};

pub const NCA0_MAGIC: [u8; 4] = *b"NCA0";
pub const NCA2_MAGIC: [u8; 4] = *b"NCA2";
pub const NCA3_MAGIC: [u8; 4] = *b"NCA3";

pub const NCA_SECTOR_SIZE: usize = 0x200;

/// NCA section entry.
#[derive(Copy, Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct NcaFsEntry {
    media_start_offset: U32,
    media_end_offset: U32,
    _reserved: [u8; 0x8],
}

static_assert!(size_of::<NcaFsEntry>() == 0x10);

/// NCA FS header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct NcaFsHeader {
    version: U16,
    fs_type: u8,
    hash_type: u8,
    encryption_type: u8,
    metadata_hash_type: u8,
    _reserved1: [u8; 0x2],
    hash_data: [u8; HASH_DATA_SIZE],
    patch_info: [BktrHeader; 2],
    generation: U32,
    secure_value: U32,
    sparse_info: [u8; 0x30],
    compression_info: [u8; 0x28],
    metadata_hash_data_info: [u8; 0x30],
    _reserved2: [u8; 0x30],
}

static_assert!(size_of::<NcaFsHeader>() == 0x200);

impl NcaFsHeader {
    pub fn verify(&self) -> Result<()> {
        ensure!(self.version.get() == 2, "Invalid NCA FS version {}", self.version.get());
        Ok(())
    }

    #[inline]
    pub fn fs_type(&self) -> NcaFsType { NcaFsType::from_u8(self.fs_type) }

    #[inline]
    pub fn encryption_type(&self) -> NcaEncryptionType {
        NcaEncryptionType::from_u8(self.encryption_type)
    }

    #[inline]
    pub fn hash_type(&self) -> NcaHashType { NcaHashType::from_u8(self.hash_type) }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NcaFsType {
    RomFs = 0,
    PartitionFs = 1,
    Unknown = u8::MAX,
}

impl NcaFsType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => NcaFsType::RomFs,
            1 => NcaFsType::PartitionFs,
            _ => NcaFsType::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NcaFsType::RomFs => "RomFS",
            NcaFsType::PartitionFs => "PFS0",
            NcaFsType::Unknown => "Unknown",
        }
    }
}

impl Display for NcaFsType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NcaEncryptionType {
    Auto = 0,
    None = 1,
    AesXts = 2,
    AesCtr = 3,
    AesCtrEx = 4,
    AesCtrSkipLayerHash = 5,
    AesCtrExSkipLayerHash = 6,
    Unknown = u8::MAX,
}

impl NcaEncryptionType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => NcaEncryptionType::Auto,
            1 => NcaEncryptionType::None,
            2 => NcaEncryptionType::AesXts,
            3 => NcaEncryptionType::AesCtr,
            4 => NcaEncryptionType::AesCtrEx,
            5 => NcaEncryptionType::AesCtrSkipLayerHash,
            6 => NcaEncryptionType::AesCtrExSkipLayerHash,
            _ => NcaEncryptionType::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NcaEncryptionType::Auto => "Auto",
            NcaEncryptionType::None => "None",
            NcaEncryptionType::AesXts => "XTS",
            NcaEncryptionType::AesCtr => "CTR",
            NcaEncryptionType::AesCtrEx => "BKTR",
            NcaEncryptionType::AesCtrSkipLayerHash => "CTR (Skip Layer Hash)",
            NcaEncryptionType::AesCtrExSkipLayerHash => "BKTR (Skip Layer Hash)",
            NcaEncryptionType::Unknown => "Unknown",
        }
    }
}

impl Display for NcaEncryptionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NcaHashType {
    Auto = 0,
    None = 1,
    HierarchicalSha256 = 2,
    HierarchicalIntegrity = 3,
    AutoSha3 = 4,
    HierarchicalSha3256 = 5,
    HierarchicalIntegritySha3 = 6,
    Unknown = u8::MAX,
}

impl NcaHashType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => NcaHashType::Auto,
            1 => NcaHashType::None,
            2 => NcaHashType::HierarchicalSha256,
            3 => NcaHashType::HierarchicalIntegrity,
            4 => NcaHashType::AutoSha3,
            5 => NcaHashType::HierarchicalSha3256,
            6 => NcaHashType::HierarchicalIntegritySha3,
            _ => NcaHashType::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NcaHashType::Auto => "Auto",
            NcaHashType::None => "None",
            NcaHashType::HierarchicalSha256 => "Hierarchical SHA-256",
            NcaHashType::HierarchicalIntegrity => "Hierarchical Integrity",
            NcaHashType::AutoSha3 => "Auto SHA-3",
            NcaHashType::HierarchicalSha3256 => "Hierarchical SHA3-256",
            NcaHashType::HierarchicalIntegritySha3 => "Hierarchical Integrity SHA-3",
            NcaHashType::Unknown => "Unknown",
        }
    }
}

impl Display for NcaHashType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }
}

/// NCA header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct NcaHeader {
    fixed_key_sig: [u8; 0x100],
    npdm_key_sig: [u8; 0x100],
    magic: [u8; 4],
    distribution_type: u8,
    content_type: u8,
    key_generation_old: u8,
    key_area_encryption_key_index: u8,
    content_size: U64,
    program_id: U64,
    content_index: U32,
    sdk_addon_version: U32,
    key_generation: u8,
    signature_key_generation: u8,
    _reserved1: [u8; 0xE],
    rights_id: [u8; 0x10],
    fs_entries: [NcaFsEntry; 4],
    fs_header_hashes: [[u8; 0x20]; 4],
    encrypted_keys: [[u8; 0x10]; 4],
    _reserved2: [u8; 0xC0],
}

static_assert!(size_of::<NcaHeader>() == 0x400);

pub fn process_nca<R>(reader: &mut R, keyset: &KeySet) -> Result<()>
where R: Read + Seek + ?Sized {
    // Read the NCA header and FS headers
    let header_key = keyset.header_key()?;
    let mut xts_reader = DecryptReader::new(&mut *reader, AesXtsDecryptor::new(&header_key));
    let mut nca_header: NcaHeader =
        read_from(&mut xts_reader).context("Failed to read NCA header")?;
    let fs_headers = match nca_header.magic {
        NCA0_MAGIC => bail!("Unimplemented: NCA0"),
        NCA2_MAGIC => {
            // Each header is individually encrypted with sector 0 as IV
            let mut fs_headers: [NcaFsHeader; 4] =
                read_from(reader).context("Failed to read NCA FS headers")?;
            for fs_header in &mut fs_headers {
                // TODO: do we need this check?
                // if fs_header._reserved2.iter().any(|&x| x != 0) {
                aes_xts_decrypt(&header_key, fs_header.as_mut_bytes(), 0);
                // }
            }
            fs_headers
        }
        NCA3_MAGIC => {
            // Headers are normally encrypted with consecutive sector indices
            let fs_headers: [NcaFsHeader; 4] =
                read_from(&mut xts_reader).context("Failed to read NCA FS headers")?;
            fs_headers
        }
        _ => panic!("Unknown NCA magic: {:?}", nca_header.magic),
    };
    for (idx, (fs_header, fs_header_hash)) in
        fs_headers.iter().zip(&nca_header.fs_header_hashes).enumerate()
    {
        if fs_header_hash.iter().all(|&x| x == 0) {
            // Empty section
            continue;
        }
        let digest: [u8; 0x20] = Sha256::digest(fs_header.as_bytes()).into();
        ensure!(
            digest == *fs_header_hash,
            "Invalid NCA FS header hash {idx}: {digest:?} != {fs_header_hash:?}"
        );
        fs_header.verify().with_context(|| format!("Failed to verify NCA FS header {idx}"))?;
    }

    // println!("{:?}", nca_header);

    // Verify the fixed key signature
    let signature = Signature::try_from(nca_header.fixed_key_sig.as_slice())
        .context("Failed to parse fixed key RSA signature")?;
    let fixed_key_modulus = NCA_KEYS_RETAIL
        .nca_hdr_fixed_key_moduli
        .get(nca_header.signature_key_generation as usize)
        .context("Invalid signature key generation")?;
    let fixed_key = RsaPublicKey::new(
        BigUint::from_bytes_be(fixed_key_modulus),
        BigUint::from_bytes_le(&[1, 0, 1]),
    )
    .context("Failed to create fixed key RSA public key")?;
    VerifyingKey::<Sha256>::new(fixed_key)
        .verify(&nca_header.as_bytes()[0x200..0x400], &signature)
        .context("Failed to verify fixed key RSA signature")?;

    // Determine master key index
    let mut master_key_index = nca_header.key_generation_old;
    if nca_header.key_generation > master_key_index {
        master_key_index = nca_header.key_generation;
    }
    if master_key_index > 0 {
        // 0, 1 are both master key 0.
        master_key_index -= 1;
    }

    let has_rights_id = nca_header.rights_id.iter().any(|&x| x != 0);
    let key_area = if !has_rights_id {
        // Decrypt key area
        let kaek =
            keyset.key_area_key(master_key_index, nca_header.key_area_encryption_key_index)?;
        aes_ecb_decrypt(&kaek, nca_header.encrypted_keys.as_mut_bytes());
        nca_header.encrypted_keys
    } else {
        // Decrypt title key
        let title_kek = keyset.title_kek(master_key_index)?;
        let mut title_key = keyset.title_key(nca_header.rights_id)?;
        aes_ecb_decrypt(&title_kek, &mut title_key);
        [[0u8; 0x10], [0u8; 0x10], title_key, [0u8; 0x10]]
    };

    for (fs_entry, fs_header) in nca_header.fs_entries.iter().zip(fs_headers.iter()) {
        if fs_entry.media_start_offset.get() == 0 {
            // Empty section
            continue;
        }
        let fs_start = fs_entry.media_start_offset.get() as u64 * NCA_SECTOR_SIZE as u64;
        let fs_end = fs_entry.media_end_offset.get() as u64 * NCA_SECTOR_SIZE as u64;
        let reader = WindowedReader::new(&mut *reader, fs_start, fs_end - fs_start)
            .context("Failed to seek to NCA FS")?;
        let reader: Box<dyn Reader> = match fs_header.encryption_type() {
            NcaEncryptionType::None => Box::new(reader),
            NcaEncryptionType::AesCtr => {
                let mut nonce: [u8; 0x10] = [0u8; 0x10];
                *array_ref_mut!(nonce, 0, 4) = fs_header.secure_value.get().to_be_bytes();
                *array_ref_mut!(nonce, 4, 4) = fs_header.generation.get().to_be_bytes();
                *array_ref_mut!(nonce, 8, 8) = (fs_start >> 4).to_be_bytes();
                Box::new(DecryptReader::new(reader, AesCtrDecryptor::new(&key_area[2], &nonce)))
            }
            NcaEncryptionType::AesXts => {
                let mut key: [u8; 0x20] = [0u8; 0x20];
                *array_ref_mut!(key, 0, 0x10) = key_area[0];
                *array_ref_mut!(key, 0x10, 0x10) = key_area[1];
                Box::new(DecryptReader::new(reader, AesXtsDecryptor::new(&key)))
            }
            NcaEncryptionType::Unknown => {
                bail!("Unknown encryption type: {}", fs_header.encryption_type);
            }
            encryption_type => {
                bail!("Unimplemented encryption type: {}", encryption_type);
            }
        };
        let mut reader: Box<dyn Reader> = match fs_header.hash_type() {
            NcaHashType::None => reader,
            NcaHashType::HierarchicalSha256 => {
                let hash_data = HierarchicalSha256Data::ref_from_bytes(&fs_header.hash_data)
                    .expect("Invalid hash data alignment");
                Box::new(HierarchicalSha256Reader::new(reader, hash_data)?)
            }
            NcaHashType::HierarchicalIntegrity => {
                let hash_data = IntegrityMetaInfo::ref_from_bytes(&fs_header.hash_data)
                    .expect("Invalid hash data alignment");
                // TODO: Implement IVFC
                let data_level = &hash_data.levels[5];
                Box::new(WindowedReader::new(
                    reader,
                    data_level.logical_offset.get(),
                    fs_end - data_level.logical_offset.get(),
                )?)
            }
            NcaHashType::Unknown => {
                bail!("Unknown hash type: {}", fs_header.hash_type);
            }
            hash_type => {
                bail!("Unimplemented hash type: {}", hash_type);
            }
        };
        match fs_header.fs_type() {
            NcaFsType::RomFs => {
                process_romfs(&mut reader)?;
            }
            NcaFsType::PartitionFs => {
                for file in process_pfs0(&mut reader)? {
                    println!("{}: Offset {:#X}, size {:#X}", file.name, file.offset, file.size);
                    if file.name == "main" {
                        let mut window = WindowedReader::new(&mut reader, file.offset, file.size)
                            .expect("Failed to seek to file");
                        let mut out = std::fs::File::create("main")?;
                        std::io::copy(&mut window, &mut out)?;
                    }
                }
            }
            NcaFsType::Unknown => {
                panic!("Invalid partition type: {}, {}", fs_header.fs_type, fs_header.fs_type);
            }
        }
    }

    Ok(())
}
