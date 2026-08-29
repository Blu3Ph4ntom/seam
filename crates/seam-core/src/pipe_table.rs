//! PipeTable — logical metadata for DataPipe, no payload.

use std::collections::HashMap;

use crate::ids::{PeerId, PipeId};
use crate::limits::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeState {
    Active { producer: PeerId, consumer: PeerId },
    ProducerEscrow { transfer: crate::ids::TransferId },
    ConsumerEscrow { transfer: crate::ids::TransferId },
    Closed,
}

pub struct PipeTable {
    pipes: HashMap<PipeId, (usize, PipeState)>,
    limits: Limits,
}

impl PipeTable {
    pub fn new(limits: Limits) -> Self {
        Self {
            pipes: HashMap::new(),
            limits,
        }
    }

    pub fn create(
        &mut self,
        pid: PipeId,
        capacity: usize,
        producer: PeerId,
        consumer: PeerId,
    ) -> Result<(), &'static str> {
        if capacity == 0 || capacity > self.limits.max_pipe_capacity {
            return Err("invalid capacity");
        }
        if self.pipes.len() >= self.limits.max_pipes_per_peer {
            return Err("too many pipes");
        }
        if self.pipes.contains_key(&pid) {
            return Err("already exists");
        }
        self.pipes
            .insert(pid, (capacity, PipeState::Active { producer, consumer }));
        Ok(())
    }

    pub fn get(&self, pid: &PipeId) -> Option<(usize, PipeState)> {
        self.pipes.get(pid).copied()
    }

    pub fn len(&self) -> usize {
        self.pipes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pipes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{PeerId, PipeId};
    use crate::limits::Limits;

    fn pid(n: u8) -> PeerId {
        PeerId([n; 16])
    }
    fn pipe(n: u8) -> PipeId {
        PipeId([n; 16])
    }

    #[test]
    fn create_and_lookup() {
        let mut t = PipeTable::new(Limits::default());
        let id = pipe(1);
        t.create(id, 4096, pid(1), pid(2)).unwrap();
        assert_eq!(
            t.get(&id),
            Some((
                4096,
                PipeState::Active {
                    producer: pid(1),
                    consumer: pid(2)
                }
            ))
        );
    }

    #[test]
    fn duplicate_rejected() {
        let mut t = PipeTable::new(Limits::default());
        let id = pipe(1);
        t.create(id, 1024, pid(1), pid(2)).unwrap();
        assert!(t.create(id, 1024, pid(1), pid(2)).is_err());
    }

    #[test]
    fn invalid_capacity_rejected() {
        let mut t = PipeTable::new(Limits::default());
        assert!(t.create(pipe(1), 0, pid(1), pid(2)).is_err());
        assert!(t.create(pipe(2), 32 * 1024 * 1024, pid(1), pid(2)).is_err());
    }
}
