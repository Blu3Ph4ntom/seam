use getrandom::fill as getrandom_fill;

macro_rules! define_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub fn fresh() -> Self {
                let mut b = [0u8; 16];
                getrandom_fill(&mut b).expect("OS entropy failed");
                Self(b)
            }
            pub fn from_bytes(b: [u8; 16]) -> Self {
                Self(b)
            }
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}({:02x}{:02x}..)",
                    stringify!($name),
                    self.0[0],
                    self.0[1]
                )
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for b in &self.0 {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    };
}

define_id!(PeerId, "Fabric-assigned peer nonce (never PID).");
define_id!(
    EndpointId,
    "Logical endpoint object identity (stable across transfers)."
);
define_id!(ResourceId, "Native resource lineage identity.");
define_id!(RegionId, "Shared backing object identity.");
define_id!(PipeId, "DataPipe object identity.");
define_id!(
    TransferId,
    "One transfer bundle identity (never an object identity)."
);

/// Lane-local routing ordinal, NOT a global identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub u64);

/// Per-endpoint request correlation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub u64);

/// Within-bundle attachment slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttachmentIndex(pub u16);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_unique_and_stable() {
        let a = PeerId::fresh();
        let b = PeerId::fresh();
        assert_ne!(a, b);
        let c = PeerId::from_bytes(a.0);
        assert_eq!(a, c);
    }
}
