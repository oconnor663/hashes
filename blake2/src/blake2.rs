macro_rules! blake2_impl {
    (
        $state:ident, $fix_state:ident, $word:ident, $bytes:ident,
        $vardoc:expr, $doc:expr, $params_type:ty, $state_type:ty,
    ) => {
        use digest::{Input, BlockInput, FixedOutput, VariableOutput, Reset};
        use digest::InvalidOutputSize;
        use digest::generic_array::GenericArray;
        use digest::generic_array::typenum::Unsigned;
        use byte_tools::copy;
        use crypto_mac::{Mac, MacResult, InvalidKeyLength};

        type Output = GenericArray<u8, $bytes>;

        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $state {
            params: $params_type,
            state: $state_type,
            output_size: usize,
        }

        impl $state {
            /// Creates a new hashing context with a key.
            ///
            /// **WARNING!** If you plan to use it for variable output MAC, then
            /// make sure to compare codes in constant time! It can be done
            /// for example by using `subtle` crate.
            pub fn new_keyed(key: &[u8], output_size: usize) -> Self {
                let mut params = <$params_type>::new();
                params.hash_length(output_size);
                params.key(key);
                Self {
                    state: params.to_state(),
                    params,
                    output_size,
                }
            }

            /// Updates the hashing context with more data.
            fn update(&mut self, data: &[u8]) {
                self.state.update(data);
            }

            fn finalize(self) -> Output {
                let hash = self.state.finalize();
                let mut out = GenericArray::default();
                copy(hash.as_bytes(), &mut out);
                out
            }
        }

        impl Default for $state {
            fn default() -> Self { Self::new_keyed(&[], $bytes::to_usize()) }
        }

        impl BlockInput for $state {
            type BlockSize = $bytes;
        }

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                self.update(data.as_ref());
            }
        }

        impl VariableOutput for $state {
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size == 0 || output_size > $bytes::to_usize() {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_keyed(&[], output_size))
            }

            fn output_size(&self) -> usize {
                self.output_size
            }

            fn variable_result<F: FnOnce(&[u8])>(self, f: F) {
                let n = self.output_size;
                let res = self.finalize();
                f(&res[..n]);
            }
        }

        impl  Reset for $state {
            fn reset(&mut self) {
                self.state = self.params.to_state();
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);


        #[derive(Clone)]
        #[doc=$doc]
        pub struct $fix_state {
            state: $state,
        }

        impl Default for $fix_state {
            fn default() -> Self {
                let state = $state::new_keyed(&[], $bytes::to_usize());
                Self { state }
            }
        }

        impl BlockInput for $fix_state {
            type BlockSize = $bytes;
        }

        impl Input for $fix_state {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                self.state.update(data.as_ref());
            }
        }

        impl FixedOutput for $fix_state {
            type OutputSize = $bytes;

            fn fixed_result(self) -> Output {
                self.state.finalize()
            }
        }

        impl  Reset for $fix_state {
            fn reset(&mut self) {
                self.state.reset()
            }
        }

        impl Mac for $fix_state {
            type OutputSize = $bytes;
            type KeySize = $bytes;

            fn new(key: &GenericArray<u8, $bytes>) -> Self {
                let state = $state::new_keyed(key, $bytes::to_usize());
                Self { state }
            }

            fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                if key.len() > $bytes::to_usize() {
                    Err(InvalidKeyLength)
                } else {
                    let state = $state::new_keyed(key, $bytes::to_usize());
                    Ok(Self { state })
                }
            }

            fn input(&mut self, data: &[u8]) { self.state.update(data); }

            fn reset(&mut self) {
                <Self as Reset>::reset(self)
            }

            fn result(self) -> MacResult<Self::OutputSize> {
                MacResult::new(self.state.finalize())
            }
        }

        impl_opaque_debug!($fix_state);
        impl_write!($fix_state);
    }
}
