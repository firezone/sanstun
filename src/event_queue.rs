use crate::Event;

/// How many events are queued before the oldest is dropped.
const MAX_QUEUED_EVENTS: usize = 16;

/// A ring buffer of the newest [`MAX_QUEUED_EVENTS`] events.
#[derive(Default)]
pub(crate) struct EventQueue {
    slots: [Option<Event>; MAX_QUEUED_EVENTS],
    head: usize,
    len: usize,
}

impl EventQueue {
    /// Appends `event`, overwriting the oldest one when full.
    pub(crate) fn push(&mut self, event: Event) {
        self.slots[(self.head + self.len) % MAX_QUEUED_EVENTS] = Some(event);

        if self.len == MAX_QUEUED_EVENTS {
            self.head = (self.head + 1) % MAX_QUEUED_EVENTS;
        } else {
            self.len += 1;
        }
    }

    /// Removes the oldest event.
    pub(crate) fn pop(&mut self) -> Option<Event> {
        if self.len == 0 {
            return None;
        }

        let event = self.slots[self.head].take();
        self.head = (self.head + 1) % MAX_QUEUED_EVENTS;
        self.len -= 1;

        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HandshakeResponseMessage;
    use crate::message::HANDSHAKE_RESP_SZ;

    #[test]
    fn empty_queue_pops_nothing() {
        assert!(EventQueue::default().pop().is_none());
    }

    #[test]
    fn events_come_out_oldest_first() {
        let mut queue = EventQueue::default();

        push_all(&mut queue, 0..3);

        assert_eq!(drain(&mut queue), [0, 1, 2]);
    }

    #[test]
    fn full_queue_drops_the_oldest() {
        let mut queue = EventQueue::default();

        push_all(&mut queue, 0..20);

        assert_eq!(drain(&mut queue), (4..20).collect::<Vec<_>>());
    }

    #[test]
    fn wraps_around_after_interleaved_push_and_pop() {
        let mut queue = EventQueue::default();

        push_all(&mut queue, 0..10);
        for expected in 0..5 {
            assert_eq!(queue.pop().map(id), Some(expected));
        }
        push_all(&mut queue, 10..30);

        assert_eq!(drain(&mut queue), (14..30).collect::<Vec<_>>());
    }

    fn push_all(queue: &mut EventQueue, ids: std::ops::Range<u8>) {
        for id in ids {
            queue.push(Event::HandshakeResponse(HandshakeResponseMessage(
                [id; HANDSHAKE_RESP_SZ],
            )));
        }
    }

    fn drain(queue: &mut EventQueue) -> Vec<u8> {
        std::iter::from_fn(|| queue.pop()).map(id).collect()
    }

    fn id(event: Event) -> u8 {
        match event {
            Event::HandshakeResponse(response) => response[0],
            other => panic!("expected a handshake response, got {other:?}"),
        }
    }
}
