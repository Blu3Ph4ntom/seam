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
            hello_version: 1,
        }
    }
}
