use digest::generic_array::typenum::U64;

blake2_impl!(VarBlake2b, Blake2b, u64, U64,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
    blake2b_simd::Params, blake2b_simd::State,
);

impl VarBlake2b {
    #[doc(hidden)]
    pub fn finalize_last_node(mut self) -> Output {
        self.state.set_last_node(true);
        self.finalize()
    }
}

impl Blake2b {
    #[doc(hidden)]
    pub fn finalize_last_node(mut self) -> Output {
        self.state.state.set_last_node(true);
        self.state.finalize()
    }
}
