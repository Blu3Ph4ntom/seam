use authority_fabric::{Endpoint, EpId, Limits, RuntimeInner};

fn consume(e: Endpoint) {
    let _ = e;
}

fn main() {
    let sh = RuntimeInner::__for_tests(Limits::default());
    let ep = Endpoint::__unchecked(EpId(42), sh);
    consume(ep);
    let _ = ep.call(vec![1], std::time::Duration::from_secs(1)); //~ ERROR E0382
}
