use authority_fabric::{Endpoint, EpId, Limits, RuntimeInner};

fn main() {
    let sh = RuntimeInner::__for_tests(Limits::default());
    let ep = Endpoint::__unchecked(EpId::from_raw([1; 16]), sh);
    let _ = ep.clone(); //~ ERROR
}
