use super::{CompressionLevel, CompressionType, gzip::StoredFallbackGzip};
use crate::io::SafeSliceExt;
use gzp::ZWriter;
use std::io::Write;

const GZ_BLOCK_SIZE: usize = 1024 * 1024;

pub enum CompressionWriter<'a, W: Write + Send + 'static> {
    None(W),
    Gz {
        buffered: usize,
        writer: gzp::par::compress::ParCompress<'a, StoredFallbackGzip, W>,
    },
    Xz {
        writes: usize,
        writer: Box<lzma_rust2::XzWriterMt<W>>,
    },
    Lzip {
        writes: usize,
        writer: Box<lzma_rust2::LzipWriterMt<W>>,
    },
    Bz2(bzip2::write::BzEncoder<W>),
    Lz4(lzzzz::lz4f::WriteCompressor<W>),
    Zstd {
        writes: usize,
        multithreaded: bool,
        writer: zstd::Encoder<'a, W>,
    },
}

impl<'a, W: Write + Send + 'static> CompressionWriter<'a, W> {
    pub fn new(
        writer: W,
        compression_type: CompressionType,
        compression_level: CompressionLevel,
        threads: usize,
    ) -> std::io::Result<Self> {
        let threads = crate::threading::resolve_threads(threads);

        Ok(match compression_type {
            CompressionType::None => CompressionWriter::None(writer),
            CompressionType::Gz => CompressionWriter::Gz {
                buffered: 0,
                writer: gzp::par::compress::ParCompressBuilder::new()
                    .num_threads(threads)
                    .map_err(std::io::Error::other)?
                    .buffer_size(GZ_BLOCK_SIZE)
                    .map_err(std::io::Error::other)?
                    .compression_level(gzp::Compression::new(compression_level.to_deflate_level()))
                    .from_writer(writer),
            },
            CompressionType::Xz => CompressionWriter::Xz {
                writes: 0,
                writer: Box::new(lzma_rust2::XzWriterMt::new(
                    writer,
                    {
                        let mut options =
                            lzma_rust2::XzOptions::with_preset(compression_level.to_xz_level());
                        options.set_block_size(Some(unsafe {
                            std::num::NonZeroU64::new_unchecked(128 * 1024)
                        }));

                        options
                    },
                    threads as u32,
                )?),
            },
            CompressionType::Lzip => CompressionWriter::Lzip {
                writes: 0,
                writer: Box::new(lzma_rust2::LzipWriterMt::new(
                    writer,
                    {
                        let mut options =
                            lzma_rust2::LzipOptions::with_preset(compression_level.to_lzip_level());
                        options.set_member_size(Some(unsafe {
                            std::num::NonZeroU64::new_unchecked(128 * 1024)
                        }));

                        options
                    },
                    threads as u32,
                )?),
            },
            CompressionType::Bz2 => CompressionWriter::Bz2(bzip2::write::BzEncoder::new(
                writer,
                bzip2::Compression::new(compression_level.to_bz2_level()),
            )),
            CompressionType::Lz4 => CompressionWriter::Lz4(lzzzz::lz4f::WriteCompressor::new(
                writer,
                lzzzz::lz4f::PreferencesBuilder::new()
                    .compression_level(compression_level.to_lz4_level())
                    .build(),
            )?),
            CompressionType::Zstd => CompressionWriter::Zstd {
                writes: 0,
                multithreaded: threads > 1,
                writer: {
                    let mut encoder =
                        zstd::Encoder::new(writer, compression_level.to_zstd_level())?;
                    if threads > 1 {
                        encoder.multithread(threads as u32).ok();
                    }

                    encoder
                },
            },
        })
    }

    pub fn finish(self) -> std::io::Result<W> {
        match self {
            CompressionWriter::None(writer) => Ok(writer),
            CompressionWriter::Gz { mut writer, .. } => {
                Ok(writer.finish().map_err(std::io::Error::other)?)
            }
            CompressionWriter::Xz { writer, .. } => Ok(writer.finish()?),
            CompressionWriter::Lzip { writer, .. } => Ok(writer.finish()?),
            CompressionWriter::Bz2(writer) => Ok(writer.finish()?),
            CompressionWriter::Lz4(mut writer) => {
                writer.flush()?;
                Ok(writer.into_inner())
            }
            CompressionWriter::Zstd { writer, .. } => Ok(writer.finish()?),
        }
    }
}

impl<'a, W: Write + Send + 'static> Write for CompressionWriter<'a, W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CompressionWriter::None(writer) => writer.write(buf),
            CompressionWriter::Gz { buffered, writer } => {
                // gzp only cuts a block once its buffer is over the block size, which
                // grows (and copies) the buffer on every block. Ending each block exactly
                // at the block size and flushing it hands the buffer off without a copy.
                let room = GZ_BLOCK_SIZE - *buffered;
                let written = writer.write(buf.get_slice(..buf.len().min(room))?)?;

                *buffered += written;
                if *buffered == GZ_BLOCK_SIZE {
                    writer.flush()?;
                    *buffered = 0;
                }

                Ok(written)
            }
            CompressionWriter::Xz { writes, writer } => {
                *writes += 1;

                if *writes % 64 == 0 {
                    writer.flush()?;
                }

                writer.write(buf)
            }
            CompressionWriter::Lzip { writes, writer } => {
                *writes += 1;

                if *writes % 64 == 0 {
                    writer.flush()?;
                }

                writer.write(buf)
            }
            CompressionWriter::Bz2(writer) => writer.write(buf),
            CompressionWriter::Lz4(writer) => writer.write(buf),
            CompressionWriter::Zstd {
                writes,
                multithreaded,
                writer,
            } => {
                if *multithreaded {
                    *writes += 1;

                    if *writes % 64 == 0 {
                        writer.flush()?;
                    }
                }

                writer.write(buf)
            }
        }
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            CompressionWriter::None(writer) => writer.flush(),
            CompressionWriter::Gz { buffered, writer } => {
                *buffered = 0;
                writer.flush()
            }
            CompressionWriter::Xz { writer, .. } => writer.flush(),
            CompressionWriter::Lzip { writer, .. } => writer.flush(),
            CompressionWriter::Bz2(writer) => writer.flush(),
            CompressionWriter::Lz4(writer) => writer.flush(),
            CompressionWriter::Zstd { writer, .. } => writer.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn random(len: usize) -> Vec<u8> {
        let mut state = 0x9e37u64;

        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    // CompressionWriter

    #[test]
    fn gz_roundtrips_uneven_writes_across_blocks() {
        let input = random(GZ_BLOCK_SIZE * 3 + 1);
        let before_flush = [1, 4095, GZ_BLOCK_SIZE + 17, 300_001];
        let after_flush = [65_537, 7, 1_000_000];
        let consumed: usize = before_flush.iter().chain(after_flush.iter()).sum();

        for threads in [1, 4] {
            let mut writer = CompressionWriter::new(
                Vec::new(),
                CompressionType::Gz,
                CompressionLevel::BestSpeed,
                threads,
            )
            .expect("writer");
            let mut offset = 0;

            for size in before_flush {
                writer
                    .write_all(input.get_slice(offset..offset + size).expect("slice"))
                    .expect("write");
                offset += size;
            }
            writer.flush().expect("flush");
            for size in after_flush {
                writer
                    .write_all(input.get_slice(offset..offset + size).expect("slice"))
                    .expect("write");
                offset += size;
            }
            writer
                .write_all(input.get_slice(consumed..).expect("slice"))
                .expect("write");

            let compressed = writer.finish().expect("finish");
            let mut decoded = Vec::new();
            flate2::read::MultiGzDecoder::new(compressed.as_slice())
                .read_to_end(&mut decoded)
                .expect("decode");

            assert!(
                decoded == input,
                "roundtrip mismatch with {threads} threads"
            );
        }
    }
}
