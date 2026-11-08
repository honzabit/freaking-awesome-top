//! Safe, reversible actions with a persisted journal. OWNER: actions agent.
use crate::model::{ActionKind, ActionRecord, Snapshot};

pub struct Actions {}

impl Actions {
    /// Journal at dirs::state_dir()|data_local_dir()/fat/actions.jsonl
    pub fn open() -> Actions { todo!() }
    /// Apply an action. `nice` required for Renice. Refuses protected pids (0, 1, self, kernel_task, WindowServer, launchd, loginwindow).
    pub fn apply(&mut self, _kind: ActionKind, _pid: u32, _nice: Option<i32>, _snap: &Snapshot) -> ActionRecord { todo!() }
    /// Undo by id (pause->resume, renice->restore). Kill is not undoable.
    pub fn undo(&mut self, _id: u64) -> ActionRecord { todo!() }
    pub fn undo_last(&mut self) -> Option<ActionRecord> { todo!() }
    /// Most recent first.
    pub fn log(&self) -> Vec<ActionRecord> { todo!() }
}
