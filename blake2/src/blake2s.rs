use digest::generic_array::typenum::U32;

blake2_impl!(VarBlake2s, Blake2s, u32, U32,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
    blake2s_simd::Params, blake2s_simd::State,
);

impl VarBlake2s {
    #[doc(hidden)]
    pub fn finalize_last_node(mut self) -> Output {
        self.state.set_last_node(true);
        self.finalize()
    }
}

impl Blake2s {
    #[doc(hidden)]
    pub fn finalize_last_node(mut self) -> Output {
        self.state.state.set_last_node(true);
        self.state.finalize()
    }
}
