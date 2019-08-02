use digest::generic_array::typenum::U32;

blake2_impl!(VarBlake2s, Blake2s, u32, U32,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
    blake2s_simd,
);
