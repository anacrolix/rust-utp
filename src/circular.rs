//! Port of libutp's SizableCircularBuffer: a power-of-two ring indexed by
//! (wrapping) sequence numbers. Slots hold `Option<T>`; growing re-homes the
//! live window so indices keep resolving to the same entries.

pub struct CircularBuffer<T> {
    /// Always a power of 2 minus one; size is mask + 1.
    mask: usize,
    slots: Vec<Option<T>>,
}

impl<T> CircularBuffer<T> {
    pub fn new() -> Self {
        let mut slots = Vec::new();
        slots.resize_with(16, || None);
        CircularBuffer { mask: 15, slots }
    }

    pub fn size(&self) -> usize {
        self.mask + 1
    }

    pub fn get(&self, i: usize) -> Option<&T> {
        self.slots[i & self.mask].as_ref()
    }

    pub fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        self.slots[i & self.mask].as_mut()
    }

    pub fn put(&mut self, i: usize, v: Option<T>) {
        let mask = self.mask;
        self.slots[i & mask] = v;
    }

    pub fn take(&mut self, i: usize) -> Option<T> {
        let mask = self.mask;
        self.slots[i & mask].take()
    }

    /// `item` contains the element we want to make space for, `index` is its
    /// distance back from the start of the live window (see libutp
    /// SizableCircularBuffer::grow).
    pub fn ensure_size(&mut self, item: usize, index: usize) {
        if index > self.mask {
            self.grow(item, index);
        }
    }

    fn grow(&mut self, item: usize, index: usize) {
        let mut size = self.mask + 1;
        loop {
            size *= 2;
            if index < size {
                break;
            }
        }
        let new_mask = size - 1;
        let mut new_slots: Vec<Option<T>> = Vec::new();
        new_slots.resize_with(size, || None);
        for i in 0..=self.mask {
            let src = item.wrapping_sub(index).wrapping_add(i);
            new_slots[src & new_mask] = self.slots[src & self.mask].take();
        }
        self.mask = new_mask;
        self.slots = new_slots;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_preserves_window() {
        let mut b: CircularBuffer<u32> = CircularBuffer::new();
        // Fill a window starting at a sequence number that wraps the mask.
        let base = 0xfff8usize;
        for i in 0..16 {
            b.put(base + i, Some(i as u32));
        }
        // Now grow to fit an entry 20 past the base.
        b.ensure_size(base + 20, 20);
        assert!(b.size() >= 32);
        for i in 0..16 {
            assert_eq!(b.get(base + i).copied(), Some(i as u32));
        }
        b.put(base + 20, Some(99));
        assert_eq!(b.get(base + 20).copied(), Some(99));
    }

    #[test]
    fn wrapping_index_aliases() {
        let mut b: CircularBuffer<u32> = CircularBuffer::new();
        b.put(3, Some(7));
        assert_eq!(b.get(3 + 16).copied(), Some(7));
        assert_eq!(b.take(3).unwrap(), 7);
        assert!(b.get(3).is_none());
    }
}
