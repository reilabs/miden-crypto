#[cfg(all(target_feature = "sve", feature = "sve"))]
pub mod optimized {
    use crate::Felt;
    use crate::hash::rescue::STATE_WIDTH;

    #[link(name = "rpo_sve", kind = "static")]
    extern "C" {
        fn add_constants_and_apply_sbox(
            state: *mut std::ffi::c_ulong,
            constants: *const std::ffi::c_ulong,
        ) -> bool;
        fn add_constants_and_apply_inv_sbox(
            state: *mut std::ffi::c_ulong,
            constants: *const std::ffi::c_ulong,
        ) -> bool;
    }

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        unsafe {
            add_constants_and_apply_sbox(state.as_mut_ptr() as *mut u64, ark.as_ptr() as *const u64)
        }
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        unsafe {
            add_constants_and_apply_inv_sbox(state.as_mut_ptr() as *mut u64, ark.as_ptr() as *const u64)
        }
    }
}

#[cfg(target_feature = "avx2")]
pub mod x86_64_avx2;

#[cfg(target_feature = "avx2")]
pub mod optimized {
    use crate::Felt;
    use crate::hash::rescue::STATE_WIDTH;
    use super::x86_64_avx2::{
        apply_inv_sbox as optimized_inv_sbox, apply_sbox as optimized_sbox,
    };

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        add_constants(state, ark);
        unsafe {
            optimized_sbox(std::mem::transmute(state));
        }
        true
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        add_constants(state, ark);
        unsafe {
            optimized_inv_sbox(std::mem::transmute(state));
        }
        true
    }

}

#[cfg(not(any(target_feature = "avx2", all(target_feature = "sve", feature = "sve"))))]
pub mod optimized {
    use crate::Felt;
    use crate::hash::rescue::STATE_WIDTH;

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        _state: &mut [Felt; STATE_WIDTH],
        _ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        false
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        _state: &mut [Felt; STATE_WIDTH],
        _ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        false
    }
}
