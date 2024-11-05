use std::{
    io,
    io::{ Read, Seek, SeekFrom},
};

/// Creates a fixed-size array reference from a slice.
#[macro_export]
macro_rules! array_ref {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline(always)]
        fn to_array<T>(slice: &[T]) -> &[T; $size] {
            unsafe { &*(slice.as_ptr() as *const [_; $size]) }
        }
        to_array(&$slice[$offset..$offset + $size])
    }};
}

/// Creates a mutable fixed-size array reference from a slice.
#[macro_export]
macro_rules! array_ref_mut {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline(always)]
        fn to_array<T>(slice: &mut [T]) -> &mut [T; $size] {
            unsafe { &mut *(slice.as_ptr() as *mut [_; $size]) }
        }
        to_array(&mut $slice[$offset..$offset + $size])
    }};
}

/// Compile-time assertion.
#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = core::assert!($condition);
    };
}

/// A read stream with a fixed window.
#[derive(Clone)]
pub struct WindowedReader<T>
where T: Read + Seek
{
    base: T,
    pos: u64,
    begin: u64,
    end: u64,
}

impl<T> WindowedReader<T>
where T: Read + Seek
{
    /// Creates a new windowed stream with offset and size.
    ///
    /// Seeks underlying stream immediately.
    #[inline]
    pub fn new(mut base: T, offset: u64, size: u64) -> io::Result<Self> {
        base.seek(SeekFrom::Start(offset))?;
        Ok(Self { base, pos: offset, begin: offset, end: offset + size })
    }

    /// Returns the length of the window.
    #[inline]
    #[allow(unused, clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 { self.end - self.begin }
}

impl<T> Read for WindowedReader<T>
where T: Read + Seek
{
    #[inline]
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = out.len().min((self.end - self.pos) as usize);
        if len == 0 {
            return Ok(0);
        }
        let len = self.base.read(&mut out[..len])?;
        self.pos += len as u64;
        Ok(len)
    }
}

impl<T> Seek for WindowedReader<T>
where T: Read + Seek
{
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut pos = match pos {
            SeekFrom::Start(p) => self.begin + p,
            SeekFrom::End(p) => self.end.saturating_add_signed(p),
            SeekFrom::Current(p) => self.pos.saturating_add_signed(p),
        };
        if pos < self.begin {
            pos = self.begin;
        } else if pos > self.end {
            pos = self.end;
        }
        let result = self.base.seek(SeekFrom::Start(pos))?;
        self.pos = result;
        Ok(result - self.begin)
    }

    #[inline]
    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.pos) }
}
