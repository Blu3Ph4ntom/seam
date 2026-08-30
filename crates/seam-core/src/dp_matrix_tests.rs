//! DP matrix unit tests — not cross-process, but verify codec and credit invariants.

#[cfg(test)]
mod dp_tests {
    use crate::credit::CreditTracker;
    use crate::datapipe::{decode_one, encode_data, Decoded, Record};

    #[test]
    fn dp01_basic_flow() {
        let mut credit = CreditTracker::new(4096).unwrap();
        let data = b"hello world";
        let grant = credit.reserve(data.len()).unwrap();
        assert_eq!(grant, data.len());
        let enc = encode_data(&data[..grant], 4096).unwrap();
        let (rec, _) = match decode_one(&enc, 4096).unwrap() {
            Decoded::Complete { record, consumed } => (record, consumed),
            _ => panic!("need more"),
        };
        assert_eq!(rec, Record::Data(data.to_vec()));
        credit.commit(grant).unwrap();
        assert_eq!(credit.outstanding(), grant);
        credit.on_consumed(grant).unwrap();
        assert_eq!(credit.available(), 4096);
    }

    #[test]
    fn dp04_capacity_exact() {
        let mut c = CreditTracker::new(1024).unwrap();
        let g = c.reserve(1024).unwrap();
        assert_eq!(g, 1024);
        c.commit(1024).unwrap();
        assert_eq!(c.available(), 0);
        assert_eq!(c.outstanding(), 1024);
    }

    #[test]
    fn dp05_blocks_when_exhausted() {
        let mut c = CreditTracker::new(100).unwrap();
        c.reserve(100).unwrap();
        c.commit(100).unwrap();
        assert_eq!(c.available(), 0);
        assert_eq!(c.reserve(10).unwrap(), 0); // no credit
    }

    #[test]
    fn dp14_oversized_rejected() {
        let big = vec![0u8; 2000];
        assert!(encode_data(&big, 1024).is_err());
    }

    #[test]
    fn dp15_excess_credit_rejected() {
        let mut c = CreditTracker::new(100).unwrap();
        c.reserve(50).unwrap();
        c.commit(50).unwrap();
        assert!(c.return_credit(100).is_err());
    }
}
