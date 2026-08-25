//! Compile-fail proof: a DataPipe Consumer consumed by a transfer-shaped
//! move cannot be used afterwards (E0382).

use authority_fabric::data_pipe::Consumer;
use authority_fabric::data_pipe::Producer;

fn transfer_like_move(_c: Consumer) {}

fn main() {
    let (_p, c) = Producer::new(4096).unwrap();
    transfer_like_move(c);
    let _ = c.try_read(&mut [0u8; 4]); //~ ERROR E0382
}
