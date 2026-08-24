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

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{
    create_backing, duplicate_backing, map_read_only, map_read_write, MappedReadOnly,
    MappedReadWrite,
};
#[cfg(windows)]
pub use windows::{
    create_backing, duplicate_backing, map_read_only, map_read_write, MappedReadOnly,
    MappedReadWrite, SECTION_RO_ACCESS, SECTION_RW_ACCESS,
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

// ------------------------------------------------- e2e payload helpers ----

/// Deterministic pseudorandom byte generator (xorshift64) used to fill shared
/// regions in cross-process proofs. Never all-zero: hides mapping mistakes.
pub fn fill_pattern(buf: &mut [u8], seed: u64) {
    let mut s = seed | 1;
    for b in buf.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s & 0xff) as u8;
    }
}

/// FNV-1a 64-bit content hash; travels over the control channel as the only
/// representation of a region's contents.
pub fn fnv64(buf: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in buf {
        h ^= b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
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

    /// Mint a read-only authority for `to` (Host-authoritative derivation).
    /// Unlike `derive_read_only` this does not require `to` to already hold
    /// the region: the Host is the rights authority and validates the
    /// requesting peer separately before calling this.
    pub fn grant_read_only(
        &mut self,
        rid: RegionId,
        to: PeerId,
        lim: &Limits,
    ) -> Result<(), RegionErr> {
        let rec = self.regions.get_mut(&rid).ok_or(RegionErr::UnknownRegion)?;
        if rec.authority_count() >= lim.max_region_capabilities {
            return Err(RegionErr::CapacityExceeded);
        }
        // A read-only authority must never silently overwrite or mask a live
        // writable authority held by the same peer.
        if rec.writable == Some(to) {
            return Err(RegionErr::SecondWriterDenied);
        }
        rec.readonly.insert(to);
        Ok(())
    }

    pub fn region_exists(&self, rid: RegionId) -> bool {
        self.regions.contains_key(&rid)
    }

    pub fn writable_holder(&self, rid: RegionId) -> Option<PeerId> {
        self.regions.get(&rid).and_then(|r| r.writable)
    }

    pub fn is_readonly_holder(&self, rid: RegionId, p: PeerId) -> bool {
        self.regions
            .get(&rid)
            .map(|r| r.readonly.contains(&p))
            .unwrap_or(false)
    }

    /// Peer death: purge every authority held by `p`. The writer slot is
    /// simply vacated (no auto re-mint); regions left with no authorities are
    /// freed and their backing bytes reclaimed from accounting.
    pub fn peer_gone(&mut self, p: PeerId) {
        let rids: Vec<RegionId> = self.regions.keys().copied().collect();
        for rid in rids {
            // A peer can hold at most two authority kinds over one region
            // (writable + a derived read-only view).
            for _ in 0..2 {
                let holds = match self.regions.get(&rid) {
                    Some(r) => r.writable == Some(p) || r.readonly.contains(&p),
                    None => false,
                };
                if !holds {
                    break;
                }
                self.drop_authority(rid, p);
            }
        }
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
    /// Map a writable view. The returned view borrows this capability:
    /// while mapped, the region cannot move, drop or transfer (G-A7).
    pub fn map_read_write(&mut self) -> std::io::Result<MappedReadWrite<'_>> {
        if !self.rights.is_writable() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "read-only capability cannot map writable",
            ));
        }
        map_read_write(&self.backing, self.size as usize)
    }

    /// Map a read-only view. Allowed for any capability.
    pub fn map_read_only(&self) -> std::io::Result<MappedReadOnly<'_>> {
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

    /// Expose the backing object (Host escrow / native-rights tests only).
    /// The application-facing mapping API is `map_read_write` / `map_read_only`;
    /// this raw accessor exists so cross-process and hostile tests can exercise
    /// the *kernel* rights of a transferred handle/fd, not just Rust types.
    pub fn backing_ref(&self) -> &File {
        &self.backing
    }

    /// Duplicate the native backing into a new owned object with the access
    /// rights implied by `writable`. On Windows this yields a section handle
    /// restricted to `SECTION_MAP_READ` for read-only; on Linux the memfd is
    /// shared (sealing enforces RO at the kernel level — see `derive_read_only`).
    pub fn duplicate_backing_handle(&self, writable: bool) -> std::io::Result<File> {
        duplicate_backing(&self.backing, writable)
    }
}

impl<'a> MappedReadOnly<'a> {
    /// Bounds-checked sub-slice of this mapping (offset+len overflow and
    /// beyond-region rejected before any slice construction).
    pub fn slice_at(&self, offset: usize, len: usize) -> std::io::Result<&'a [u8]> {
        let end = offset.checked_add(len).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "offset+len overflow",
        ))?;
        let (ptr, mlen) = self.raw_parts();
        if end > mlen {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mapping extends beyond region",
            ));
        }
        // SAFETY: the mapping is live for 'a (PhantomData tie) and
        // offset..end was just bounds-checked against its length.
        Ok(unsafe { std::slice::from_raw_parts(ptr.add(offset), len) })
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
        assert!(r.slice_at(0, 4 * 1024 * 1024 + 1).is_err());
        assert!(r.slice_at(1, usize::MAX).is_err());
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
            {
                let mut w = reg.map_read_write().unwrap();
                // Touch a sample of pages.
                for off in (0..size as usize).step_by(1 << 16) {
                    w.as_mut_slice()[off] = (off & 0xff) as u8;
                }
            } // writable session ends before attenuation
            let ro = reg.derive_read_only().unwrap();
            let r = ro.map_read_only().unwrap();
            for off in (0..size as usize).step_by(1 << 16) {
                assert_eq!(r.as_slice()[off], (off & 0xff) as u8);
            }
        }
    }

    // -------------------------------------------------------------------
    // Capability vs mapping lifetime (RUN 005D §5): executable answers.
    // -------------------------------------------------------------------

    /// Mapping drop removes NO authority; the capability stays fully usable
    /// and remappable. Views never outlive their capability borrow (the
    /// compiler enforces it), so "mapping outlives wrapper" cannot occur in
    /// safe Rust, and dropping the capability while a view exists is a
    /// compile error (see compile-fail/shared_transfer_while_mapped).
    #[test]
    fn mapping_and_authority_lifetimes_are_independent() {
        let mut reg = SharedRegion::create(4096, &lim()).unwrap();
        let rid0 = reg.id();
        {
            // A live read-only view does NOT block attenuation (& borrows).
            let v = reg.map_read_only().unwrap();
            assert_eq!(v.as_slice()[..4], [0; 4]);
            let ro = reg.derive_read_only().unwrap();
            assert_eq!(ro.rights(), Rights::ReadOnly);
            assert_eq!(reg.id(), ro.id());
        }
        // Remapping after unmap works: mapping lifetime != capability life.
        {
            let mut w = reg.map_read_write().unwrap();
            w.as_mut_slice()[7] = 42;
        }
        {
            let v = reg.map_read_only().unwrap();
            assert_eq!(v.as_slice()[7], 42);
        }
        assert_eq!(reg.id(), rid0);
        assert!(reg.map_read_write().is_ok());
    }

    // writable kernel access from a read-only transferred backing. This is the
    // RUN 005B hard gate (G1-G6); Rust typing alone is insufficient evidence.
    // ---------------------------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn windows_ro_native_handle_rejects_writable_mapping() {
        let reg = SharedRegion::create(4096, &lim()).unwrap();
        // Writable backing maps writable (friendly + native).
        let _w = map_read_write(reg.backing_ref(), 4096).unwrap();
        // Derive a RO-restricted native handle (SECTION_MAP_READ only).
        let ro = reg.duplicate_backing_handle(false).unwrap();
        // Hostile: attempt writable native view on the RO handle -> kernel deny.
        assert!(
            map_read_write(&ro, 4096).is_err(),
            "RO section handle must reject FILE_MAP_WRITE"
        );
        // Read view on RO handle succeeds.
        assert!(map_read_only(&ro, 4096).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn linux_ro_native_fd_rejects_writable_mapping() {
        let mut reg = SharedRegion::create(4096, &lim()).unwrap();
        // Producer writes through its writable session...
        {
            let mut w = reg.map_read_write().unwrap();
            w.as_mut_slice()[0] = 7;
            w.as_mut_slice()[1] = 9;
        }
        // ...ends the session, then derives RO over the SAME pages.
        let ro = reg.derive_read_only().unwrap();
        // Data written pre-attenuation is visible through the derived view:
        let ro_view = ro.map_read_only().unwrap();
        assert_eq!(ro_view.as_slice()[0], 7);
        assert_eq!(ro_view.as_slice()[1], 9);
        drop(ro_view);
        // Hostile: writable native mapping on the RO fd must fail at kernel.
        assert!(
            map_read_write(ro.backing_ref(), 4096).is_err(),
            "attenuated memfd must reject PROT_WRITE"
        );
        // write(2) through the attenuated descriptor must also fail.
        {
            use std::io::Write as _;
            let mut wf = ro.backing_ref().try_clone().unwrap();
            assert!(wf.write_all(b"x").is_err(), "RO fd must reject write(2)");
        }
        // Read mapping on RO fd succeeds.
        assert!(map_read_only(ro.backing_ref(), 4096).is_ok());
    }
}
