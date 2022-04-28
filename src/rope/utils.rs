use std::collections::HashSet;

/// A randomly start counter which will detect duplication.
/// This counter only use last 24 bits of u32.
#[derive(Debug)]
pub struct NoDupSenderIdCounter {
    allocated: HashSet<u32>,
    next_id: u32,
}

impl NoDupSenderIdCounter {
    pub fn new() -> Self {
        Self {
            allocated: HashSet::new(),
            next_id: rand::random::<u32>() & !(0xff << 24),
        }
    }

    pub fn check(&self, id: u32) -> bool {
        self.allocated.contains(&id)
    }

    pub fn check_and_set(&mut self, id: u32) -> bool {
        if !self.check(id) {
            self.allocated.insert(id);
            false
        } else {
            true
        }
    }

    pub fn uncheck(&mut self, id: u32) {
        self.allocated.remove(&id);
    }

    pub fn next(&mut self) -> Option<u32> {
        let mut next_id = self.next_id;
        loop {
            next_id = if next_id < (1<<24) {
                next_id + 1
            } else {
                0
            };
            if !self.check_and_set(self.next_id) {
                let current_id = self.next_id;
                self.next_id = next_id;
                break Some(current_id);
            } else if self.next_id == next_id {
                // That means there is no slot for new id
                break None;
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NoDupSenderIdCounter;

    #[test]
    fn counter_should_have_another_idx_after_return_an_idx(){
        let mut counter = NoDupSenderIdCounter::new();
        assert!(counter.next().is_some());
        assert!(counter.next().is_some());
    }
}
