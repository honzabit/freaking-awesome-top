//! The in-memory index: one compact node per *kept* directory. Files are aggregated into
//! their parent (only big / top files keep a name), and small completed subtrees are folded
//! into their parent, so millions of files cost a few thousand nodes.
//!
//! Sizes: `own` = this dir's inode + its files + folded subdirs; `total` = own + kept children
//! (mount children excluded), valid once the node is `Done`. While a node is being (re)scanned
//! its previous `total` (if any, `at > 0`) is what callers see, flagged partial; a node never
//! measured shows a live lower bound computed from what is known so far.

use super::sys::BigFile;
use crate::model::Ts;

pub type Id = u32;
pub const NONE: Id = u32::MAX;

pub const F_MOUNT: u16 = 1; // another filesystem / alias: excluded from the parent's total
pub const F_PROTECTED: u16 = 2; // TCC-protected, skipped
pub const F_DENIED: u16 = 4; // could not be read (EACCES/EPERM)
pub const F_EXPAND: u16 = 8; // the user looks here: keep all children + top files on completion
pub const F_FOLDED: u16 = 16; // `own` contains folded subdirectories
pub const F_MATERIALIZE: u16 = 32; // created under an already-measured parent that counted it
pub const F_DIRTY: u16 = 64; // changed since the last cache flush
pub const F_PERSISTED: u16 = 128; // has a row in the cache
pub const F_DESCEND: u16 = 256; // mount that is scanned as its own tree
pub const F_COUNTED: u16 = 512; // counted in the parent's `pending`

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Agg {
    pub size: u64,
    pub apparent: u64,
    pub files: u64,
    pub newest: i64,
    pub denied: u32,
}

impl Agg {
    pub fn add(&mut self, o: &Agg) {
        self.size += o.size;
        self.apparent += o.apparent;
        self.files += o.files;
        self.newest = self.newest.max(o.newest);
        self.denied += o.denied;
    }
    pub fn sub_sat(&mut self, o: &Agg) {
        self.size = self.size.saturating_sub(o.size);
        self.apparent = self.apparent.saturating_sub(o.apparent);
        self.files = self.files.saturating_sub(o.files);
        self.denied = self.denied.saturating_sub(o.denied);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Not read in the current pass (skeleton, or reset for a refresh).
    Unvisited,
    Queued,
    Reading,
    /// Read; waiting for `pending` subdirectories.
    Waiting,
    Done,
}

#[derive(Debug)]
pub struct Node {
    pub name: Box<[u8]>,
    pub parent: Id,
    pub children: Vec<Id>,
    pub big: Vec<BigFile>,
    pub own: Agg,
    pub total: Agg,
    /// When `total` was measured (0 = never).
    pub at: Ts,
    pub dev: u64,
    pub ino: u64,
    /// The directory's own mtime / ctime, ns (change detection).
    pub mtime: i64,
    pub ctime: i64,
    /// This directory inode's own blocks (from the parent's stat).
    pub self_size: u64,
    pub self_apparent: u64,
    pub stamp: u32,
    pub pending: u32,
    pub flags: u16,
    pub depth: u16,
    pub state: State,
    pub live: bool,
}

impl Node {
    fn blank(stamp: u32) -> Node {
        Node {
            name: Box::default(),
            parent: NONE,
            children: Vec::new(),
            big: Vec::new(),
            own: Agg::default(),
            total: Agg::default(),
            at: 0,
            dev: 0,
            ino: 0,
            mtime: 0,
            ctime: 0,
            self_size: 0,
            self_apparent: 0,
            stamp,
            pending: 0,
            flags: 0,
            depth: 0,
            state: State::Unvisited,
            live: true,
        }
    }
    pub fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }
    pub fn in_flight(&self) -> bool {
        matches!(self.state, State::Queued | State::Reading | State::Waiting)
    }
}

pub struct Tree {
    pub nodes: Vec<Node>,
    free: Vec<Id>,
}

pub const ROOT: Id = 0;

impl Tree {
    pub fn new() -> Tree {
        Tree { nodes: vec![Node::blank(1)], free: Vec::new() }
    }

    pub fn n(&self, id: Id) -> &Node {
        &self.nodes[id as usize]
    }
    pub fn m(&mut self, id: Id) -> &mut Node {
        &mut self.nodes[id as usize]
    }
    pub fn valid(&self, id: Id, stamp: u32) -> bool {
        (id as usize) < self.nodes.len() && self.n(id).live && self.n(id).stamp == stamp
    }
    #[allow(dead_code)]
    pub fn kept(&self) -> usize {
        self.nodes.len() - self.free.len()
    }

    pub fn alloc(&mut self, parent: Id, name: &[u8]) -> Id {
        let id = self.alloc_raw(parent, name);
        self.m(parent).children.push(id);
        id
    }

    /// Allocate a node under `parent` without linking it into `parent.children`.
    pub fn alloc_raw(&mut self, parent: Id, name: &[u8]) -> Id {
        let depth = self.n(parent).depth.saturating_add(1);
        let id = match self.free.pop() {
            Some(id) => {
                let stamp = self.n(id).stamp.wrapping_add(1);
                self.nodes[id as usize] = Node::blank(stamp);
                id
            }
            None => {
                self.nodes.push(Node::blank(1));
                (self.nodes.len() - 1) as Id
            }
        };
        let n = self.m(id);
        n.name = name.into();
        n.parent = parent;
        n.depth = depth;
        id
    }

    /// Free `id` and its subtree (the caller unlinks it from its parent's children).
    /// Returns the paths of persisted nodes so their cache rows can be deleted.
    pub fn free_subtree(&mut self, id: Id, removed: &mut Vec<Vec<u8>>) {
        if self.n(id).has(F_PERSISTED) {
            removed.push(self.path(id));
        }
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            let n = self.m(x);
            n.live = false;
            n.stamp = n.stamp.wrapping_add(1);
            stack.extend(std::mem::take(&mut n.children));
            n.big = Vec::new();
            n.name = Box::default();
            self.free.push(x);
        }
    }

    /// Unlink `id` from its parent and free it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn remove(&mut self, id: Id, removed: &mut Vec<Vec<u8>>) {
        let p = self.n(id).parent;
        if p != NONE {
            self.m(p).children.retain(|&c| c != id);
        }
        self.free_subtree(id, removed);
    }

    pub fn path(&self, id: Id) -> Vec<u8> {
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut x = id;
        while x != ROOT && x != NONE {
            let n = self.n(x);
            parts.push(&n.name);
            x = n.parent;
        }
        if parts.is_empty() {
            return b"/".to_vec();
        }
        let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 1).sum());
        for p in parts.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(p);
        }
        out
    }

    pub fn child(&self, id: Id, name: &[u8]) -> Option<Id> {
        self.n(id).children.iter().copied().find(|&c| &*self.n(c).name == name)
    }

    pub fn find(&self, path: &[u8]) -> Option<Id> {
        let mut x = ROOT;
        for comp in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            x = self.child(x, comp)?;
        }
        Some(x)
    }

    /// Find `path`, creating missing (skeleton, `Unvisited`) nodes. Nodes created under a
    /// parent that already counted folded subdirs are flagged `F_MATERIALIZE`.
    pub fn find_or_create(&mut self, path: &[u8]) -> Id {
        let mut x = ROOT;
        for comp in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            x = match self.child(x, comp) {
                Some(c) => c,
                None => {
                    let parent_counted = {
                        let p = self.n(x);
                        p.state == State::Done && p.has(F_FOLDED)
                    };
                    let c = self.alloc(x, comp);
                    if parent_counted {
                        self.m(c).flags |= F_MATERIALIZE;
                    }
                    c
                }
            };
        }
        x
    }

    /// What a parent sums for child `id`.
    pub fn contribution(&self, id: Id) -> Agg {
        let n = self.n(id);
        if n.has(F_MOUNT) {
            return Agg::default();
        }
        if n.state == State::Done {
            return n.total;
        }
        // Being re-measured: callers see its previous totals (`display`), so its parent
        // must count at least those, not the restarted lower bound.
        let l = self.live(id);
        if n.at > 0 && n.total.size > l.size { n.total } else { l }
    }

    /// Lower bound from what is known now.
    pub fn live(&self, id: Id) -> Agg {
        let n = self.n(id);
        let mut a = n.own;
        for &c in &n.children {
            a.add(&self.contribution(c));
        }
        a
    }

    /// (numbers, partial, measured_at) as callers see them.
    pub fn display(&self, id: Id, now: Ts) -> (Agg, bool, Ts) {
        let n = self.n(id);
        match n.state {
            State::Done => (n.total, false, n.at),
            _ if n.at > 0 => (n.total, true, n.at),
            _ => (self.live(id), true, now),
        }
    }

    pub fn recompute(&mut self, id: Id) {
        let mut a = self.n(id).own;
        for i in 0..self.n(id).children.len() {
            let c = self.n(id).children[i];
            a.add(&self.contribution(c));
        }
        self.m(id).total = a;
    }

    /// Ids in the subtree of `id` (preorder, including `id`).
    pub fn subtree(&self, id: Id) -> Vec<Id> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            out.push(x);
            stack.extend(self.n(x).children.iter().copied());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_find() {
        let mut t = Tree::new();
        let a = t.find_or_create(b"/a/b/c");
        assert_eq!(t.path(a), b"/a/b/c");
        assert_eq!(t.find(b"/a/b/c"), Some(a));
        assert_eq!(t.find(b"/a/b/"), t.find(b"/a/b"));
        assert_eq!(t.path(ROOT), b"/");
        assert_eq!(t.n(a).depth, 3);
        let mut removed = Vec::new();
        let b = t.find(b"/a/b").unwrap();
        t.remove(b, &mut removed);
        assert!(t.find(b"/a/b").is_none());
        assert_eq!(t.kept(), 2);
        let again = t.find_or_create(b"/a/x");
        assert!(t.valid(again, t.n(again).stamp));
    }
}
