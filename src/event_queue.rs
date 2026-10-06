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
