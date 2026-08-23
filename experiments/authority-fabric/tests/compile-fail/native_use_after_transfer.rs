//! Compile-fail proof that NativeFile is move-only: use after the value has
//! been consumed by a transfer-shaped `fn consume(NativeFile)` must fail
//! with E0382 (use of moved value).

use authority_fabric::native::NativeFile;

fn consume(_f: NativeFile) {}

fn main() {
    let file = NativeFile::new_temp(b"nonce").unwrap();
    consume(file);
    let _ = file.read_all();
}
