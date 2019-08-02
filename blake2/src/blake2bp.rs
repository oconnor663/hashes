use digest::generic_array::typenum::U64;

blake2_impl!(VarBlake2bp, Blake2bp, u64, U64,
    "Blake2bp instance with a variable output.",
    "Blake2b instance with a fixed output.",
    blake2b_simd::blake2bp::Params, blake2b_simd::blake2bp::State,
);
