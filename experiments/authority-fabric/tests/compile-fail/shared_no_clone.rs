use authority_fabric::limits::Limits;
use authority_fabric::shared::SharedRegion;

fn main() {
    let reg = SharedRegion::create(4096, &Limits::default()).unwrap();
    // Authority duplication is never implicit: no Clone on SharedRegion.
    let twin = reg.clone(); //~ ERROR the trait `Clone` is not implemented
    let _ = (reg, twin);
}
