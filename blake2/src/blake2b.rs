use digest::generic_array::typenum::U64;

blake2_impl!(VarBlake2b, Blake2b, u64, U64,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
    blake2b_simd,
);
