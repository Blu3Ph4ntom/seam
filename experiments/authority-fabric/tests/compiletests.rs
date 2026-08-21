//! Compile-fail proof that Endpoint is move-only (gate G7).

#[test]
fn moved_endpoint_cannot_be_used() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/*.rs");
}
