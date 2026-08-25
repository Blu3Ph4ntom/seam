//! Compile-fail proof: a DataPipe Producer consumed by a transfer-shaped
//! move cannot be used afterwards (E0382). Transfer takes the authority by
//! value, so use-after-transfer is unrepresentable in safe code.

use authority_fabric::data_pipe::Producer;

fn transfer_like_move(_p: Producer) {}

fn main() {
    let (p, _c) = Producer::new(4096).unwrap();
    transfer_like_move(p);
    let _ = p.try_write(b"x"); //~ ERROR E0382
}
