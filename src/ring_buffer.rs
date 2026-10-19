/// A fixed-capacity queue of the newest `N` items.
pub(crate) struct RingBuffer<T, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T, const N: usize> RingBuffer<T, N> {
    pub(crate) fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            head: 0,
            len: 0,
        }
    }

    /// Appends `item`, overwriting the oldest one when full.
    pub(crate) fn push_back(&mut self, item: T) {
        self.slots[(self.head + self.len) % N] = Some(item);

        if self.len == N {
            self.head = (self.head + 1) % N;
        } else {
            self.len += 1;
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Removes the oldest item.
    pub(crate) fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        let item = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;

        item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_pops_nothing() {
        assert!(RingBuffer::<u8, 4>::new().pop_front().is_none());
    }

    #[test]
    fn items_come_out_oldest_first() {
        let mut buffer = RingBuffer::<u8, 4>::new();

        push_all(&mut buffer, 0..3);

        assert_eq!(drain(&mut buffer), [0, 1, 2]);
    }

    #[test]
    fn full_buffer_drops_the_oldest() {
        let mut buffer = RingBuffer::<u8, 4>::new();

        push_all(&mut buffer, 0..6);

        assert_eq!(drain(&mut buffer), [2, 3, 4, 5]);
    }

    #[test]
    fn wraps_around_after_interleaved_push_and_pop() {
        let mut buffer = RingBuffer::<u8, 4>::new();

        push_all(&mut buffer, 0..3);
        assert_eq!(buffer.pop_front(), Some(0));
        assert_eq!(buffer.pop_front(), Some(1));
        push_all(&mut buffer, 3..8);

        assert_eq!(drain(&mut buffer), [4, 5, 6, 7]);
    }

    fn push_all(buffer: &mut RingBuffer<u8, 4>, items: std::ops::Range<u8>) {
        for item in items {
            buffer.push_back(item);
        }
    }

    fn drain(buffer: &mut RingBuffer<u8, 4>) -> Vec<u8> {
        std::iter::from_fn(|| buffer.pop_front()).collect()
    }
}
