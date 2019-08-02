use digest::generic_array::typenum::U32;

blake2_impl!(VarBlake2sp, Blake2sp, u32, U32,
    "Blake2sp instance with a variable output.",
    "Blake2s instance with a fixed output.",
    blake2s_simd::blake2sp::Params, blake2s_simd::blake2sp::State,
);
