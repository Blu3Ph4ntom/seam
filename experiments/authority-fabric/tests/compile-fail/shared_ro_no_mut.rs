use authority_fabric::limits::Limits;
use authority_fabric::shared::SharedRegion;

fn main() {
    let reg = SharedRegion::create(4096, &Limits::default()).unwrap();
    let ro = reg.derive_read_only().unwrap();
    let view = ro.map_read_only().unwrap();
    // A read-only mapping exposes only an immutable slice; there is no
    // mutable-access API to escalate through.
    let bytes: &mut [u8] = view.as_mut_slice(); //~ ERROR no method named `as_mut_slice`
    bytes[0] = 0;
}
