use crate::io::{SafeSliceMutExt, UninterruptedReadExt};
use bytes::Bytes;
use futures::{Stream, ready};
use std::{
    future::Future,
    io::Read,
    pin::Pin,
    task::{Context, Poll},
};

/// Yields exactly `len` bytes, zero-padding a reader that ends early so `Content-Length` holds.
pub struct ReadStream<R> {
    state: State<R>,
    remaining: u64,
    chunk_size: usize,
}

enum State<R> {
    Idle(Option<R>),
    Busy(tokio::task::JoinHandle<(R, std::io::Result<Vec<u8>>)>),
    Done,
}

impl<R: Read + Send + Unpin + 'static> ReadStream<R> {
    pub fn new(reader: R, len: u64, chunk_size: usize) -> Self {
        Self {
            state: State::Idle(Some(reader)),
            remaining: len,
            chunk_size: chunk_size.max(1),
        }
    }
}

/// Reads up to `len` bytes, zero-padding the rest.
pub fn read_chunk(reader: &mut impl Read, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buffer = crate::io::mem_buffer(len);

    let mut filled = 0;
    while filled < len {
        match reader.read_uninterrupted(buffer.get_slice_mut(filled..)?)? {
            0 => break,
            n => filled += n,
        }
    }

    Ok(buffer)
}

impl<R: Read + Send + Unpin + 'static> Stream for ReadStream<R> {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                State::Idle(reader) => {
                    let Some(mut reader) = reader.take().filter(|_| this.remaining > 0) else {
                        this.state = State::Done;
                        continue;
                    };

                    let len = this.remaining.min(this.chunk_size as u64) as usize;
                    this.state = State::Busy(tokio::task::spawn_blocking(move || {
                        let result = read_chunk(&mut reader, len);
                        (reader, result)
                    }));
                }
                State::Busy(handle) => {
                    let result = ready!(Pin::new(handle).poll(cx));

                    return Poll::Ready(Some(match result {
                        Ok((reader, Ok(chunk))) => {
                            this.remaining -= chunk.len() as u64;
                            this.state = State::Idle(Some(reader));

                            Ok(Bytes::from(chunk))
                        }
                        Ok((_, Err(err))) => {
                            this.state = State::Done;

                            Err(err)
                        }
                        Err(err) => {
                            this.state = State::Done;

                            Err(std::io::Error::other(err))
                        }
                    }));
                }
                State::Done => return Poll::Ready(None),
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let chunks = self.remaining.div_ceil(self.chunk_size as u64) as usize;

        match self.state {
            State::Idle(_) => (chunks, Some(chunks)),
            State::Busy(_) => (1, Some(chunks.max(1))),
            State::Done => (0, Some(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::io::{Cursor, ErrorKind};

    struct Trickle(Cursor<Vec<u8>>);

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match buf.first_mut() {
                Some(first) => self.0.read(std::slice::from_mut(first)),
                None => Ok(0),
            }
        }
    }

    struct Failing {
        kind: ErrorKind,
        remaining: usize,
    }

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            self.remaining -= 1;
            Err(std::io::Error::from(self.kind))
        }
    }

    fn collect<R: Read + Send + Unpin + 'static>(
        stream: ReadStream<R>,
    ) -> Vec<std::io::Result<Bytes>> {
        tokio_test::block_on(stream.collect::<Vec<_>>())
    }

    // ReadStream
    #[test]
    fn stream_yields_exact_content_in_bounded_chunks_when_len_not_multiple_of_chunk_size() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let items = collect(ReadStream::new(Cursor::new(data.clone()), 1000, 64));

        let chunks: Vec<Bytes> = items.into_iter().map(|item| item.unwrap()).collect();
        assert!(
            chunks
                .iter()
                .all(|chunk| !chunk.is_empty() && chunk.len() <= 64)
        );
        assert_eq!(chunks.concat(), data);
    }

    #[test]
    fn stream_pads_short_reader_with_zeros_to_len() {
        let items = collect(ReadStream::new(Cursor::new(vec![7u8; 10]), 25, 8));

        let bytes: Vec<u8> = items
            .into_iter()
            .map(|item| item.unwrap())
            .collect::<Vec<_>>()
            .concat();
        let mut expected = vec![7u8; 10];
        expected.resize(25, 0);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn stream_with_zero_len_yields_nothing() {
        let items = collect(ReadStream::new(Cursor::new(vec![1u8; 10]), 0, 8));

        assert!(items.is_empty());
    }

    #[test]
    fn stream_fills_whole_chunks_from_trickling_reader() {
        let data: Vec<u8> = (1..=20u8).collect();
        let items = collect(ReadStream::new(Trickle(Cursor::new(data.clone())), 20, 8));

        let lens: Vec<usize> = items
            .iter()
            .map(|item| item.as_ref().unwrap().len())
            .collect();
        assert_eq!(lens, vec![8, 8, 4]);
        let bytes: Vec<u8> = items
            .into_iter()
            .map(|item| item.unwrap())
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(bytes, data);
    }

    #[test]
    fn stream_yields_error_then_ends() {
        let reader = Cursor::new(vec![3u8; 4]).chain(Failing {
            kind: ErrorKind::PermissionDenied,
            remaining: usize::MAX,
        });

        tokio_test::block_on(async {
            let mut stream = ReadStream::new(reader, 12, 4);

            assert_eq!(stream.next().await.unwrap().unwrap(), vec![3u8; 4]);
            assert_eq!(
                stream.next().await.unwrap().unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
            assert!(stream.next().await.is_none());
        });
    }

    // read_chunk
    #[test]
    fn read_chunk_retries_interrupted() {
        let mut reader = Failing {
            kind: ErrorKind::Interrupted,
            remaining: 3,
        }
        .chain(Cursor::new(vec![5u8; 4]));

        assert_eq!(read_chunk(&mut reader, 4).unwrap(), vec![5u8; 4]);
    }

    #[test]
    fn read_chunk_returns_other_errors() {
        let mut reader = Cursor::new(vec![1u8; 2]).chain(Failing {
            kind: ErrorKind::BrokenPipe,
            remaining: usize::MAX,
        });

        assert_eq!(
            read_chunk(&mut reader, 4).unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }
}
