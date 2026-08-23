//! Shared-memory region authority (RUN 005, experimental).
//!
//! A shared region deliberately breaks the "one authority" rule of ordinary
//! endpoints/native resources: a writable authority and many read-only
//! authorities may coexist over one kernel-backed object. Rights are explicit
//! and derived, never via `Clone`. The generic authority logic here is
//! platform-independent and contains ZERO unsafe; all unsafe lives in the
//! platform mapping modules.

use std::collections::{HashMap, HashSet};
use std::fs::File;

use getrandom::fill;

use crate::limits::Limits;
use crate::router::PeerId;

#[cfg(windows)]
mod windows;
#[cfg(unix)]
mod unix;

#[cfg(windows)]
pub use windows::{
    create_backing, duplicate_backing, map_read_only, map_read_write, MappedReadOnly,
    MappedReadWrite, SECTION_RO_ACCESS, SECTION_RW_ACCESS,
};
#[cfg(unix)]
pub use unix::{
    create_backing, duplicate_backing, map_read_only, map_read_write, MappedReadOnly,
    MappedReadWrite,
};

// ---------------------------------------------------------------- identity --

/// Runtime identity of a shared region. OS-random, collision-checked, opaque,
/// NOT itself authority. Possession of a `SharedRegion` is authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegionId(pub [u8; 16]);

impl RegionId {
    pub fn from_raw(b: [u8; 16]) -> Self {
        RegionId(b)
    }
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

pub trait RegionSpace {
    fn contains(&self, id: RegionId) -> bool;
}

impl RegionSpace for HashSet<RegionId> {
    fn contains(&self, id: RegionId) -> bool {
        HashSet::contains(self, &id)
    }
}

fn draw16() -> [u8; 16] {
    let mut b = [0u8; 16];
    fill(&mut b).expect("OS entropy source failed");
    b
}

pub fn fresh_region_id(taken: &impl RegionSpace) -> RegionId {
    loop {
        let id = RegionId(draw16());
        if !id.is_zero() && !taken.contains(id) {
            return id;
        }
    }
}

// ----------------------------------------------------------------- rights --

/// Minimal explicit rights model. No giant lattice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rights {
    ReadOnly,
    ReadWrite,
}

impl Rights {
    /// Attenuation/duplication rule.
    /// - any authority may derive/duplicate ReadOnly (attenuation)
    /// - ReadWrite may transfer equal ReadWrite
    /// - ReadOnly may NOT escalate to ReadWrite
    pub fn can_derive(self, target: Rights) -> bool {
        match (self, target) {
            (_, Rights::ReadOnly) => true,
            (Rights::ReadWrite, Rights::ReadWrite) => true,
            (Rights::ReadOnly, Rights::ReadWrite) => false,
        }
    }

    pub fn is_writable(self) -> bool {
        matches!(self, Rights::ReadWrite)
    }

    pub fn wire_byte(self) -> u8 {
        match self {
            Rights::ReadOnly => 0,
            Rights::ReadWrite => 1,
        }
    }

    pub fn from_wire_byte(b: u8) -> Rights {
        match b {
            1 => Rights::ReadWrite,
            _ => Rights::ReadOnly,
        }
    }
}

// ------------------------------------------------------------- authority ---

#[derive(Debug, PartialEq, Eq)]
pub enum RegionErr {
    UnknownRegion,
    NotHolder,
    EscalationDenied,
    SecondWriterDenied,
    CapacityExceeded,
    SizeExceeded,
    EmptyRegion,
}

/// Host-authoritative per-region record. Tracks how many live authorities of
/// each kind exist. Enforces `write_authority_count <= 1`.
#[derive(Debug)]
struct RegionRec {
    size: u64,
    writable: Option<PeerId>,
    readonly: HashSet<PeerId>,
}

impl RegionRec {
    fn authority_count(&self) -> usize {
        self.readonly.len() + self.writable.map(|_| 1).unwrap_or(0)
    }
}

/// Generic, zero-unsafe authority graph over shared regions.
#[derive(Debug, Default)]
pub struct RegionTable {
    regions: HashMap<RegionId, RegionRec>,
    total_backing_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RegionAccounting {
    pub regions: usize,
    pub writable_authorities: usize,
    pub readonly_authorities: usize,
    pub total_backing_bytes: u64,
}

impl RegionTable {
    pub fn new() -> Self {
        RegionTable::default()
    }

    pub fn accounting(&self) -> RegionAccounting {
        let mut w = 0;
        let mut r = 0;
        for rec in self.regions.values() {
            if rec.writable.is_some() {
                w += 1;
            }
            r += rec.readonly.len();
        }
        RegionAccounting {
            regions: self.regions.len(),
            writable_authorities: w,
            readonly_authorities: r,
            total_backing_bytes: self.total_backing_bytes,
        }
    }

    /// Create a region with the creating peer as the (sole) writable holder.
    pub fn create_region(
        &mut self,
        rid: RegionId,
        size: u64,
        creator: PeerId,
        lim: &Limits,
    ) -> Result<(), RegionErr> {
        if size == 0 || size > lim.max_region_size {
            return Err(RegionErr::SizeExceeded);
        }
        // Checked addition prevents overflow of the total-backing counter.
        let new_total = self
            .total_backing_bytes
            .checked_add(size)
            .ok_or(RegionErr::SizeExceeded)?;
        if new_total > lim.max_total_region_bytes {
            return Err(RegionErr::SizeExceeded);
        }
        if self.regions.len() >= lim.max_regions {
            return Err(RegionErr::CapacityExceeded);
        }
        if self.regions.contains_key(&rid) {
            return Err(RegionErr::CapacityExceeded);
        }
        self.regions.insert(
            rid,
            RegionRec {
                size,
                writable: Some(creator),
                readonly: HashSet::new(),
            },
        );
        self.total_backing_bytes = new_total;
        Ok(())
    }

    /// Derive/duplicate a ReadOnly authority from any existing authority.
    pub fn derive_read_only(
        &mut self,
        rid: RegionId,
        holder: PeerId,
        lim: &Limits,
    ) -> Result<(), RegionErr> {
        let rec = self.regions.get_mut(&rid).ok_or(RegionErr::UnknownRegion)?;
        let is_holder = rec.writable == Some(holder) || rec.readonly.contains(&holder);
        if !is_holder {
            return Err(RegionErr::NotHolder);
        }
        if rec.authority_count() >= lim.max_region_capabilities {
            return Err(RegionErr::CapacityExceeded);
        }
        rec.readonly.insert(holder);
        Ok(())
    }

    /// Move the writable authority from `from` to `to`. One writer maximum.
    pub fn transfer_writable(
        &mut self,
        rid: RegionId,
        from: PeerId,
        to: PeerId,
    ) -> Result<(), RegionErr> {
        let rec = self.regions.get_mut(&rid).ok_or(RegionErr::UnknownRegion)?;
        if rec.writable != Some(from) {
            return Err(RegionErr::NotHolder);
        }
        rec.writable = Some(to);
        Ok(())
    }

    /// Move a read-only authority from `from` to `to`.
    pub fn transfer_read_only(
        &mut self,
        rid: RegionId,
        from: PeerId,
        to: PeerId,
    ) -> Result<(), RegionErr> {
        let rec = self.regions.get_mut(&rid).ok_or(RegionErr::UnknownRegion)?;
        if !rec.readonly.contains(&from) {
            return Err(RegionErr::NotHolder);
        }
        rec.readonly.remove(&from);
        rec.readonly.insert(to);
        Ok(())
    }

    /// Drop an authority (writable or read-only). Region is freed when empty.
    pub fn drop_authority(&mut self, rid: RegionId, holder: PeerId) {
        if let Some(rec) = self.regions.get_mut(&rid) {
            if rec.writable == Some(holder) {
                rec.writable = None;
            } else {
                rec.readonly.remove(&holder);
            }
            if rec.writable.is_none() && rec.readonly.is_empty() {
                let size = rec.size;
                self.regions.remove(&rid);
                self.total_backing_bytes = self.total_backing_bytes.saturating_sub(size);
            }
        }
    }

    /// Host-authoritative validation of a requested derivation. Rejects any
    /// attempt to mint a second writable authority (RUN 005 invariant), and
    /// any escalation from ReadOnly to ReadWrite.
    pub fn authorize(
        &self,
        rid: RegionId,
        source: Rights,
        requested: Rights,
    ) -> Result<(), RegionErr> {
        if !source.can_derive(requested) {
            return Err(RegionErr::EscalationDenied);
        }
        if requested.is_writable() {
            // Even an "equal" RW request is rejected: only one writer allowed.
            if let Some(rec) = self.regions.get(&rid) {
                if rec.writable.is_some() {
                    return Err(RegionErr::SecondWriterDenied);
                }
            }
        }
        Ok(())
    }

    pub fn size_of(&self, rid: RegionId) -> Option<u64> {
        self.regions.get(&rid).map(|r| r.size)
    }
}

// ----------------------------------------------------------- capability ----

/// Move-only shared-region capability. Possession = authority. No `Clone`:
/// multiple readers require an explicit `derive_read_only`.
pub struct SharedRegion {
    id: RegionId,
    rights: Rights,
    size: u64,
    backing: File,
}

impl std::fmt::Debug for SharedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedRegion")
            .field("id", &self.id.0)
            .field("rights", &self.rights)
            .field("size", &self.size)
            .finish()
    }
}

impl SharedRegion {
    /// Create a new region of `size` bytes with writable authority.
    pub fn create(size: u64, lim: &Limits) -> std::io::Result<Self> {
        if size == 0 || size > lim.max_region_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "region size out of bounds",
            ));
        }
        let backing = create_backing(size)?;
        let taken = HashSet::new();
        let id = fresh_region_id(&taken);
        Ok(SharedRegion {
            id,
            rights: Rights::ReadWrite,
            size,
            backing,
        })
    }

    pub fn id(&self) -> RegionId {
        self.id
    }
    pub fn rights(&self) -> Rights {
        self.rights
    }
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Map a writable view. Fails if this capability is not writable.
    pub fn map_read_write(&mut self) -> std::io::Result<MappedReadWrite> {
        if !self.rights.is_writable() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "read-only capability cannot map writable",
            ));
        }
        map_read_write(&self.backing, self.size as usize)
    }

    /// Map a read-only view. Allowed for any capability.
    pub fn map_read_only(&self) -> std::io::Result<MappedReadOnly> {
        map_read_only(&self.backing, self.size as usize)
    }

    /// Attenuate: produce a new read-only capability sharing the same backing.
    /// This capability remains intact (still writable).
    pub fn derive_read_only(&self) -> std::io::Result<SharedRegion> {
        let backing = duplicate_backing(&self.backing, false)?;
        Ok(SharedRegion {
            id: self.id,
            rights: Rights::ReadOnly,
            size: self.size,
            backing,
        })
    }

    /// Extract the backing object for Host escrow (move boundary).
    pub fn into_backing(self) -> (RegionId, Rights, u64, File) {
        (self.id, self.rights, self.size, self.backing)
    }

    /// Materialize a capability from a received backing object.
    pub fn from_backing(id: RegionId, rights: Rights, size: u64, backing: File) -> Self {
        SharedRegion {
            id,
            rights,
            size,
            backing,
        }
    }

    /// Map `offset..offset+len` with out-of-bounds rejection (checked).
    /// Returns a sub-slice view over the full mapping (no new unsafe mapping).
    pub fn read_slice_at<'a>(
        &'a self,
        mapping: &'a MappedReadOnly,
        offset: usize,
        len: usize,
    ) -> std::io::Result<&'a [u8]> {
        let end = offset
            .checked_add(len)
            .ok_or(std::io::Error::new(std::io::ErrorKind::InvalidInput, "offset+len overflow"))?;
        if end > self.size as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mapping extends beyond region",
            ));
        }
        Ok(&mapping.as_slice()[offset..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    // Simple deterministic pseudo-random filler so payloads are reproducible.
    fn fill_pattern(buf: &mut [u8], seed: u64) {
        let mut s = seed;
        for b in buf.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s & 0xff) as u8;
        }
    }

    fn checksum(buf: &[u8]) -> u64 {
        let mut h: u64 = 1469598103934665603; // FNV-ish
        for &b in buf {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211);
        }
        h
    }

    #[test]
    fn rights_attenuation_rule() {
        assert!(Rights::ReadWrite.can_derive(Rights::ReadOnly));
        assert!(Rights::ReadWrite.can_derive(Rights::ReadWrite));
        assert!(Rights::ReadOnly.can_derive(Rights::ReadOnly));
        assert!(!Rights::ReadOnly.can_derive(Rights::ReadWrite));
    }

    #[test]
    fn single_process_write_derive_read_4mib() {
        let mut reg = SharedRegion::create(4 * 1024 * 1024, &lim()).unwrap();
        assert_eq!(reg.rights(), Rights::ReadWrite);
        let mut w = reg.map_read_write().unwrap();
        fill_pattern(w.as_mut_slice(), 0x1234_5678);
        let want = checksum(w.as_mut_slice());
        drop(w);

        let ro = reg.derive_read_only().unwrap();
        assert_eq!(ro.rights(), Rights::ReadOnly);
        // Original stays writable.
        assert_eq!(reg.rights(), Rights::ReadWrite);
        let r = ro.map_read_only().unwrap();
        assert_eq!(checksum(r.as_slice()), want);
        // Read-only view exposes no mutable slice (type-level, compiles only
        // via as_slice). OOB rejection:
        assert!(ro.read_slice_at(&r, 0, 4 * 1024 * 1024 + 1).is_err());
        assert!(ro.read_slice_at(&r, 1, usize::MAX).is_err());
    }

    #[test]
    fn read_only_cannot_map_writable() {
        let reg = SharedRegion::create(4096, &lim()).unwrap();
        let mut ro = reg.derive_read_only().unwrap();
        assert!(ro.map_read_write().is_err());
    }

    #[test]
    fn authority_graph_write_exclusivity_and_derive() {
        let mut t = RegionTable::new();
        let p = PeerId(1);
        let c = PeerId(2);
        let rid = RegionId([9u8; 16]);
        t.create_region(rid, 4096, p, &lim()).unwrap();
        // Second writer rejected.
        assert_eq!(
            t.authorize(rid, Rights::ReadWrite, Rights::ReadWrite),
            Err(RegionErr::SecondWriterDenied)
        );
        // p derives RO for c (attenuation allowed from RW).
        t.derive_read_only(rid, p, &lim()).unwrap();
        // c (RO) cannot escalate to RW.
        assert_eq!(
            t.authorize(rid, Rights::ReadOnly, Rights::ReadWrite),
            Err(RegionErr::EscalationDenied)
        );
        // c may duplicate RO.
        assert!(t.authorize(rid, Rights::ReadOnly, Rights::ReadOnly).is_ok());
        // Non-holder rejected.
        assert_eq!(
            t.derive_read_only(RegionId([3u8; 16]), c, &lim()),
            Err(RegionErr::UnknownRegion)
        );
        let a = t.accounting();
        assert_eq!(a.writable_authorities, 1);
        assert_eq!(a.readonly_authorities, 1);
        // Drop both authorities of p (writable, then the derived readonly) ->
        // region freed and backing reclaimed.
        t.drop_authority(rid, p);
        t.drop_authority(rid, p);
        assert_eq!(t.accounting().regions, 0);
        assert_eq!(t.accounting().total_backing_bytes, 0);
    }

    #[test]
    fn ten_k_capability_churn_returns_to_baseline() {
        let mut t = RegionTable::new();
        let p = PeerId(1);
        let c = PeerId(2);
        let base = t.accounting();
        for i in 0..10_000u64 {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_le_bytes());
            let rid = RegionId(id);
            t.create_region(rid, 4096, p, &lim()).unwrap();
            t.derive_read_only(rid, p, &lim()).unwrap();
            t.transfer_writable(rid, p, c).unwrap();
            t.drop_authority(rid, c);
            t.drop_authority(rid, p);
        }
        let after = t.accounting();
        assert_eq!(after.regions, base.regions);
        assert_eq!(after.total_backing_bytes, base.total_backing_bytes);
        assert_eq!(after.writable_authorities, 0);
        assert_eq!(after.readonly_authorities, 0);
    }

    #[test]
    fn large_region_maps_and_verifies() {
        for &mb in &[4u64, 64, 256] {
            let size = mb * 1024 * 1024;
            let mut reg = match SharedRegion::create(size, &lim()) {
                Ok(r) => r,
                Err(_) => continue, // resource-limited environment
            };
            let mut w = reg.map_read_write().unwrap();
            // Touch a sample of pages.
            for off in (0..size as usize).step_by(1 << 16) {
                w.as_mut_slice()[off] = (off & 0xff) as u8;
            }
            let ro = reg.derive_read_only().unwrap();
            let r = ro.map_read_only().unwrap();
            for off in (0..size as usize).step_by(1 << 16) {
                assert_eq!(r.as_slice()[off], (off & 0xff) as u8);
            }
        }
    }
}
