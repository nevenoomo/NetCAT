use serde::{Deserialize, Serialize};
use super::{PatternIdx};

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
pub enum SyncStatus {
    NoSync,
    Hit,
    Miss,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self::NoSync
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub(crate) struct TrackingContext {
    pos: PatternIdx,
    sync_status: SyncStatus,
    should_send: bool,
    is_injected: bool,
    unsynced: usize,
}

impl TrackingContext {
    #[inline(always)]
    pub(crate) fn new(init_pos: PatternIdx) -> TrackingContext {
        let mut ctx: TrackingContext = Default::default();
        ctx.pos = init_pos;
        ctx
    }
    #[inline(always)]
    pub(crate) fn pos(&self) -> PatternIdx {
        self.pos
    }
    #[inline(always)]
    pub(crate) fn sync_status(&self) -> SyncStatus {
        self.sync_status
    }
    #[inline(always)]
    pub(crate) fn should_inject(&self) -> bool {
        self.unsynced > 2 || self.should_send
    }
    #[inline(always)]
    pub(crate) fn inject(&mut self) -> &mut Self {
        self.is_injected = true;
        self
    }
    #[inline(always)]
    pub(crate) fn is_injected(&self) -> bool {
        self.is_injected
    }
    #[inline(always)]
    /// Updates the context corresponding to the successful syncronization
    pub(crate) fn sync_hit(&mut self, next_pos: PatternIdx) -> &mut Self {
        self.pos = next_pos;
        self.unsynced = 0;
        self.should_send = false;
        self.sync_status = SyncStatus::Hit;
        self
    }

    #[inline(always)]
    /// Updates the context corresponding to the missed syncronization
    pub(crate) fn sync_miss(&mut self, recovered_pos: PatternIdx) -> &mut Self {
        self.pos = recovered_pos;
        self.should_send = true;
        self.sync_status = SyncStatus::Miss;
        self
    }

    #[inline(always)]
    /// Updates the context corresponding to the missed syncronization
    pub(crate) fn unsynced_meaurement(&mut self) -> &mut Self {
        self.unsynced += 1;
        self.should_send = false;
        self.sync_status = SyncStatus::NoSync;
        self
    }
}
