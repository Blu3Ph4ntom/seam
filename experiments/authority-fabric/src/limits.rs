//! Centralized experimental limits. Not production-tuned; they exist to
//! prove resource exhaustion is part of the semantics (see RUN gates G14).

#[derive(Clone, Debug)]
pub struct Limits {
    /// Hard cap on a single frame body. The decoder checks the declared
    /// length against this BEFORE any allocation.
    pub max_frame_body: u32,
    /// Maximum attachments per DATA frame.
    pub max_attachments: usize,
    /// Maximum concurrently-live logical endpoints per runtime instance.
    pub max_live_endpoints: usize,
    /// Outbound queue bounds per peer (messages and approximate bytes).
    pub queue_max_msgs: usize,
    pub queue_max_bytes: usize,
    /// Maximum outstanding request/reply correlations per runtime.
    pub max_outstanding_requests: usize,
    /// Handshake validation values.
    pub hello_magic: u16,
    pub hello_version: u16,
    /// Recent-retirement cache size (bounded independently of churn).
    pub max_retired: usize,
    /// In-flight transfer transactions per fabric instance.
    pub max_pending_transfers: usize,
    /// Reserved control-plane queue (lifecycle/transfer); never silently dropped.
    pub control_queue_max_msgs: usize,
    pub control_queue_max_bytes: usize,
    /// Maximum live native resources per fabric (Host table).
    pub max_native_resources: usize,
    /// Maximum native resources in escrow (Host).
    pub max_resources_in_escrow: usize,
    /// Maximum live shared-memory regions per fabric instance.
    pub max_regions: usize,
    /// Maximum bytes in a single shared region (checked arithmetic; usize::MAX rejected).
    pub max_region_size: u64,
    /// Maximum live region-capability authorities per region.
    pub max_region_capabilities: usize,
    /// Maximum total mapped/backing bytes across all regions.
    pub max_total_region_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_frame_body: 64 * 1024,
            max_attachments: 8,
            max_live_endpoints: 4096,
            queue_max_msgs: 256,
            queue_max_bytes: 1024 * 1024,
            max_outstanding_requests: 64,
            hello_magic: 0x5345, // "SE"
            hello_version: 2,
            max_retired: 4096,
            max_pending_transfers: 256,
            control_queue_max_msgs: 64,
            control_queue_max_bytes: 64 * 1024,
            max_native_resources: 256,
            max_resources_in_escrow: 64,
            max_regions: 64,
            max_region_size: 256 * 1024 * 1024,
            max_region_capabilities: 16,
            max_total_region_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}
