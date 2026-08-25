#[derive(Clone, Debug)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_control_frame_bytes: usize,
    pub max_attachments: usize,
    pub max_endpoints_per_peer: usize,
    pub max_resources_per_peer: usize,
    pub max_pipes_per_peer: usize,
    pub max_total_pipe_capacity: usize,
    pub max_shared_region_bytes: usize,
    pub max_outstanding_requests: usize,
    pub max_retained_results: usize,
    pub max_transfers_in_flight: usize,
    pub max_pipe_capacity: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_control_frame_bytes: 64 * 1024,
            max_attachments: 16,
            max_endpoints_per_peer: 1024,
            max_resources_per_peer: 1024,
            max_pipes_per_peer: 1024,
            max_total_pipe_capacity: 256 * 1024 * 1024,
            max_shared_region_bytes: 512 * 1024 * 1024,
            max_outstanding_requests: 1024,
            max_retained_results: 4096,
            max_transfers_in_flight: 1024,
            max_pipe_capacity: 16 * 1024 * 1024,
        }
    }
}

impl Limits {
    pub fn check_frame(&self, len: usize) -> Result<(), &'static str> {
        if len > self.max_frame_bytes {
            return Err("frame too large");
        }
        Ok(())
    }
    pub fn check_attachments(&self, n: usize) -> Result<(), &'static str> {
        if n > self.max_attachments {
            return Err("too many attachments");
        }
        Ok(())
    }
}
