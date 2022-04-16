
/// This `std::io::Write` impl just counting the u8 written into.
pub struct WriteCounter {
    pub length: usize,
}

impl Default for WriteCounter {
    fn default() -> Self {
        Self {
            length: 0,
        }
    }
}

impl std::io::Write for WriteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.length += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) } // just ignore
}

/// A `std::io::Write` impl for `&mut [u8]`.
/// Return `std::io::ErrorKind::OutOfMemory` when no enough capacity to copy data.
pub struct BufWriter<'a> {
    buf: &'a mut [u8],
    current_pos: usize,
}

impl<'a> BufWriter<'a> {
    pub fn new(buf: &'a mut [u8], start_pos: usize) -> Self {
        Self {
            buf,
            current_pos: start_pos
        }
    }

    pub fn capacity(&self) -> usize {
        self.buf.len() - self.current_pos
    }

    pub fn rest(&mut self) -> &mut [u8] {
        &mut self.buf[self.current_pos..]
    }

    pub fn len(&self) -> usize {
        self.current_pos
    }
}

impl std::io::Write for BufWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() <= self.capacity() {
            let rest = self.rest();
            rest[..buf.len()].copy_from_slice(buf);
            self.current_pos += buf.len();
            Ok(buf.len())
        } else {
            Err(std::io::ErrorKind::OutOfMemory.into())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
