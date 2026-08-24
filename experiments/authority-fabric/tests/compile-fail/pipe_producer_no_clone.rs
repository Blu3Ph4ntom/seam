use authority_fabric::data_pipe::Producer;

fn main() {
    let (p, _c) = Producer::new(16).unwrap();
    // Producer authority is move-only: no implicit duplication.
    let twin = p.clone(); //~ ERROR the trait `Clone` is not implemented
    let _ = (p, twin);
}
