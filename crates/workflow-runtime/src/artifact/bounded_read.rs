//! One physical read boundary for all filesystem artifact comparisons and pages.

use super::{ArtifactError, ArtifactErrorKind, FilesystemArtifactStore};
use std::{fs::OpenOptions, io::Read, num::NonZeroU64, os::unix::fs::OpenOptionsExt, path::Path};

pub(super) fn read_file(path: &Path, cap: NonZeroU64) -> Result<Vec<u8>, ArtifactError> {
    // Follow existing file/directory symlinks, but never block opening a FIFO.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(FilesystemArtifactStore::storage_error)?;
    if !file
        .metadata()
        .map_err(FilesystemArtifactStore::storage_error)?
        .is_file()
    {
        return Err(ArtifactError::new(ArtifactErrorKind::Io));
    }
    read_capped(file, cap.get())
}

fn read_capped(reader: impl Read, cap: u64) -> Result<Vec<u8>, ArtifactError> {
    // Bound actual IO even if the same open file grows after metadata validation.
    // Start empty: neither metadata nor a potentially u64::MAX cap controls allocation.
    let mut bytes = Vec::new();
    reader
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(FilesystemArtifactStore::storage_error)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > cap) {
        return Err(ArtifactError::new(ArtifactErrorKind::ContentTooLarge));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{self, Write},
    };

    #[test]
    fn growing_file_reads_only_one_sentinel_byte_beyond_cap() {
        let root = super::super::bounded_read_tests::TestRoot::new();
        let path = root.0.join("growing");
        std::fs::write(&path, b"12").unwrap();
        struct GrowingFile {
            file: File,
            path: std::path::PathBuf,
            read: usize,
        }
        impl Read for GrowingFile {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let len = buffer.len().min(2);
                let read = self.file.read(&mut buffer[..len])?;
                if self.read == 0 {
                    OpenOptions::new()
                        .append(true)
                        .open(&self.path)?
                        .write_all(b"345678")?;
                }
                self.read += read;
                Ok(read)
            }
        }
        let mut reader = GrowingFile {
            file: File::open(&path).unwrap(),
            path,
            read: 0,
        };
        assert_eq!(reader.file.metadata().unwrap().len(), 2);
        assert_eq!(
            read_capped(&mut reader, 4).unwrap_err().kind(),
            ArtifactErrorKind::ContentTooLarge
        );
        assert_eq!(
            reader.read, 5,
            "actual bytes consumed, not a metadata precheck"
        );
        assert_eq!(reader.file.metadata().unwrap().len(), 8);
    }
}
