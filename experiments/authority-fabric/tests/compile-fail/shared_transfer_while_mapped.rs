use authority_fabric::limits::Limits;
use authority_fabric::shared::SharedRegion;

fn main() {
    let mut reg = SharedRegion::create(4096, &Limits::default()).unwrap();
    let mut view = reg.map_read_write().unwrap();
    // A live mutable mapping borrows the capability: the authority cannot be
    // moved, consumed or transferred while the view exists.
    let (_id, _rights, _size, backing) = reg.into_backing(); //~ ERROR E0505
    view.as_mut_slice()[0] = 1;
    drop(backing);
}
