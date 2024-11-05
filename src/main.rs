mod aes;
mod bktr;
mod hash;
mod ivfc;
mod keys;
mod nca;
mod pfs0;
mod read;
mod romfs;
mod util;

use std::{io::Seek, path::PathBuf};

use anyhow::{Context, Result};
use argp::{FromArgs, HelpStyle};

use crate::{keys::read_keyset, nca::process_nca, pfs0::process_pfs0, util::WindowedReader};

#[derive(FromArgs, Debug)]
/// A tool for working with Nintendo Switch files.
struct TopLevel {
    #[argp(positional)]
    /// The file to read.
    file: PathBuf,
}

fn main() -> Result<()> {
    let args: TopLevel = argp::parse_args_or_exit(&HelpStyle::default());
    let keyset = read_keyset().context("Failed to read keyset")?;
    let mut reader = std::fs::File::open(&args.file)
        .with_context(|| format!("Failed to open {}", args.file.display()))?;
    let files = process_pfs0(&mut reader).context("Failed to read PFS0 header")?;

    for file in &files {
        println!("{}: Offset {:#X}, size {:#X}", file.name, file.offset, file.size);
        if file.name.ends_with(".nca") {
            let mut window = WindowedReader::new(&mut reader, file.offset, file.size)
                .expect("Failed to seek to file");
            process_nca(&mut window, &keyset).expect("Failed to read NCA header");
        }
    }

    Ok(())
}
