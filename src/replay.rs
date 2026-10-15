use crate::errors::Error;
use crate::timers::REJECT_AFTER_MESSAGES;

const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 128;
const N_BITS: u64 = WORD_SIZE * N_WORDS;
const _: () = assert!(REJECT_AFTER_MESSAGES <= u64::MAX - N_BITS);

/// A sliding bitmap that rejects replays while allowing packets to arrive out of order.
#[derive(Debug, Clone)]
pub(crate) struct ReceivingKeyCounterValidator {
    /// One past the highest accepted counter.
    next: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        Self {
            next: Default::default(),
            bitmap: [0; _],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clears the word containing `idx`.
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Checks whether `counter` is unseen and within the allowed range.
    #[inline(always)]
    pub(crate) fn will_accept(&self, counter: u64) -> Result<(), Error> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::InvalidCounter);
        }
        if counter >= self.next {
            return Ok(());
        }
        if counter + N_BITS < self.next {
            return Err(Error::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(Error::DuplicateCounter)
        }
    }

    /// Rechecks `counter` against the current replay window and marks it as received.
    #[inline(always)]
    pub(crate) fn mark_did_receive(&mut self, counter: u64) -> Result<(), Error> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::InvalidCounter);
        }
        if counter + N_BITS < self.next {
            return Err(Error::InvalidCounter);
        }
        if counter == self.next {
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            if self.check_bit(counter) {
                return Err(Error::DuplicateCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Clear skipped counters so reused bitmap positions do not appear to be replays.
        if counter - self.next >= N_BITS {
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_at_or_above_the_limit_are_rejected() {
        let mut window = ReceivingKeyCounterValidator::default();

        for counter in [REJECT_AFTER_MESSAGES, u64::MAX - N_BITS, u64::MAX] {
            assert!(matches!(
                window.will_accept(counter),
                Err(Error::InvalidCounter)
            ));
            assert!(matches!(
                window.mark_did_receive(counter),
                Err(Error::InvalidCounter)
            ));
        }

        assert_eq!(window.next, 0);
        assert!(window.will_accept(0).is_ok());
    }
}
