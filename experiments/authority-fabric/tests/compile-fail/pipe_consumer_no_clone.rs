use authority_fabric::data_pipe::Consumer;
use authority_fabric::data_pipe::Producer;

fn main() {
    let (_p, c) = Producer::new(16).unwrap();
    // Consumer authority is move-only: no implicit duplication.
    let twin = c.clone(); //~ ERROR the trait `Clone` is not implemented
    let _ = (c, twin);
}
