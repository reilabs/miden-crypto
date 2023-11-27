use core::arch::x86_64::*;

// Preliminary notes:
// 1. AVX does not support addition with carry but 128-bit (2-word) addition can be easily
//    emulated. The method recognizes that for a + b overflowed iff (a + b) < a:
//        i. res_lo = a_lo + b_lo
//       ii. carry_mask = res_lo < a_lo
//      iii. res_hi = a_hi + b_hi - carry_mask
//    Notice that carry_mask is subtracted, not added. This is because AVX comparison instructions
//    return -1 (all bits 1) for true and 0 for false.
//
// 2. AVX does not have unsigned 64-bit comparisons. Those can be emulated with signed comparisons
//    by recognizing that a <u b iff a  <s b + (1 << 63), where the addition wraps around
//    and the comparisons are unsigned and signed respectively. The shift function adds/subtracts
//    1 << 63 to enable this trick.
//      Example: addition with carry.
//        i. a_lo_s = shift(a_lo)
//       ii. res_lo_s = a_lo_s + b_lo
//      iii. carry_mask = res_lo_s <s a_lo_s
//       iv. res_lo = shift(res_lo_s)
//        v. res_hi = a_hi + b_hi - carry_mask
//    The suffix _s denotes a value that has been shifted by 1 << 63. The result of addition is
//    shifted if exactly one of the operands is shifted, as is the case on line ii. Line iii.
//    performs a signed comparison res_lo_s <s a_lo_s on shifted values to emulate unsigned
//    comparison res_lo <u a_lo on unshifted values. Finally, line iv. reverses the shift so the
//    result can be returned.
//      When performing a chain of calculations, we can often save instructions by letting the shift
//    propagate through and only undoing it when necessary. For example, to compute the addition of
//    three two-word (128-bit) numbers we can do:
//        i. a_lo_s = shift(a_lo)
//       ii. tmp_lo_s = a_lo_s + b_lo
//      iii. tmp_carry_mask = tmp_lo_s <s a_lo_s
//       iv. tmp_hi = a_hi + b_hi - tmp_carry_mask
//        v. res_lo_s = tmp_lo_s + c_lo
//       vi. res_carry_mask = res_lo_s <s tmp_lo_s
//      vii. res_lo = shift(res_lo_s)
//     viii. res_hi = tmp_hi + c_hi - res_carry_mask
//    Notice that the above 3-value addition still only requires two calls to shift, just like our
//    2-value addition.

#[inline(always)]
pub fn branch_hint() {
    // NOTE: These are the currently supported assembly architectures. See the
    // [nightly reference](https://doc.rust-lang.org/nightly/reference/inline-assembly.html) for
    // the most up-to-date list.
    #[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "x86",
    target_arch = "x86_64",
    ))]
    unsafe {
        core::arch::asm!("", options(nomem, nostack, preserves_flags));
    }
}

macro_rules! map2 {
    ($f:ident::<$l:literal>, $v:ident) => {
        ($f::<$l>($v.0), $f::<$l>($v.1))
    };
    ($f:ident::<$l:literal>, $v1:ident, $v2:ident) => {
        (
            $f::<$l>($v1.0, $v2.0),
            $f::<$l>($v1.1, $v2.1),
        )
    };
    ($f:ident, $v:ident) => {
        ($f($v.0), $f($v.1))
    };
    ($f:ident, $v0:ident, $v1:ident) => {
        ($f($v0.0, $v1.0), $f($v0.1, $v1.1))
    };
    ($f:ident, rep $v0:ident, $v1:ident) => {
        ($f($v0, $v1.0), $f($v0, $v1.1))
    };

    ($f:ident, $v0:ident, rep $v1:ident) => {
        ($f($v0.0, $v1), $f($v0.1, $v1))
    };
}

#[inline(always)]
unsafe fn square3(
    x: (__m256i, __m256i, [u64; 4]),
) -> ((__m256i, __m256i, [u64; 4]), (__m256i, __m256i, [u64; 4])) {
    let z0 = x.2[0] as u128 * x.2[0] as u128;
    let z1 = x.2[1] as u128 * x.2[1] as u128;
    let z2 = x.2[2] as u128 * x.2[2] as u128;
    let z3 = x.2[3] as u128 * x.2[3] as u128;

    let z0_lo = z0 as u64;
    let z1_lo = z1 as u64;
    let z2_lo = z2 as u64;
    let z3_lo = z3 as u64;

    let x_hi = {
        // Move high bits to low position. The high bits of x_hi are ignored. Swizzle is faster than
        // bitshift. This instruction only has a floating-point flavor, so we cast to/from float.
        // This is safe and free.
        let x_ps = map2!(_mm256_castsi256_ps, x);
        let x_hi_ps = map2!(_mm256_movehdup_ps, x_ps);
        map2!(_mm256_castps_si256, x_hi_ps)
    };

    // All pairwise multiplications.
    let mul_ll = map2!(_mm256_mul_epu32, x, x);
    let mul_lh = map2!(_mm256_mul_epu32, x, x_hi);
    let mul_hh = map2!(_mm256_mul_epu32, x_hi, x_hi);

    let z0_hi = (z0 >> 64) as u64;
    let z1_hi = (z1 >> 64) as u64;
    let z2_hi = (z2 >> 64) as u64;
    let z3_hi = (z3 >> 64) as u64;

    // Bignum addition, but mul_lh is shifted by 33 bits (not 32).
    let mul_ll_hi = map2!(_mm256_srli_epi64::<33>, mul_ll);
    let t0 = map2!(_mm256_add_epi64, mul_lh, mul_ll_hi);
    let t0_hi = map2!(_mm256_srli_epi64::<31>, t0);
    let res_hi = map2!(_mm256_add_epi64, mul_hh, t0_hi);

    // Form low result by adding the mul_ll and the low 31 bits of mul_lh (shifted to the high
    // position).
    let mul_lh_lo = map2!(_mm256_slli_epi64::<33>, mul_lh);
    let res_lo = map2!(_mm256_add_epi64, mul_ll, mul_lh_lo);

    (
        (res_lo.0, res_lo.1, [z0_lo, z1_lo, z2_lo, z3_lo]),
        (res_hi.0, res_hi.1, [z0_hi, z1_hi, z2_hi, z3_hi])
    )
}

#[inline(always)]
unsafe fn mul3(
    x: (__m256i, __m256i, [u64; 4]),
    y: (__m256i, __m256i, [u64; 4]),
) -> ((__m256i, __m256i, [u64; 4]), (__m256i, __m256i, [u64; 4])) {
    let z0 = x.2[0] as u128 * y.2[0] as u128;
    let z1 = x.2[1] as u128 * y.2[1] as u128;
    let z2 = x.2[2] as u128 * y.2[2] as u128;
    let z3 = x.2[3] as u128 * y.2[3] as u128;

    let z0_lo = z0 as u64;
    let z1_lo = z1 as u64;
    let z2_lo = z2 as u64;
    let z3_lo = z3 as u64;

    let epsilon = _mm256_set1_epi64x(0xffffffff);
    let x_hi = {
        // Move high bits to low position. The high bits of x_hi are ignored. Swizzle is faster than
        // bitshift. This instruction only has a floating-point flavor, so we cast to/from float.
        // This is safe and free.
        let x_ps = map2!(_mm256_castsi256_ps, x);
        let x_hi_ps = map2!(_mm256_movehdup_ps, x_ps);
        map2!(_mm256_castps_si256, x_hi_ps)
    };
    let y_hi = {
        let y_ps = map2!(_mm256_castsi256_ps, y);
        let y_hi_ps = map2!(_mm256_movehdup_ps, y_ps);
        map2!(_mm256_castps_si256, y_hi_ps)
    };

    // All four pairwise multiplications
    let mul_ll = map2!(_mm256_mul_epu32, x, y);
    let mul_lh = map2!(_mm256_mul_epu32, x, y_hi);
    let mul_hl = map2!(_mm256_mul_epu32, x_hi, y);
    let mul_hh = map2!(_mm256_mul_epu32, x_hi, y_hi);

    let z0_hi = (z0 >> 64) as u64;
    let z1_hi = (z1 >> 64) as u64;
    let z2_hi = (z2 >> 64) as u64;
    let z3_hi = (z3 >> 64) as u64;

    // Bignum addition
    // Extract high 32 bits of mul_ll and add to mul_hl. This cannot overflow.
    let mul_ll_hi = map2!(_mm256_srli_epi64::<32>, mul_ll);
    let t0 = map2!(_mm256_add_epi64, mul_hl, mul_ll_hi);
    // Extract low 32 bits of t0 and add to mul_lh. Again, this cannot overflow.
    // Also, extract high 32 bits of t0 and add to mul_hh.
    let t0_lo = map2!(_mm256_and_si256, t0, rep epsilon);
    let t0_hi = map2!(_mm256_srli_epi64::<32>, t0);
    let t1 = map2!(_mm256_add_epi64, mul_lh, t0_lo);
    let t2 = map2!(_mm256_add_epi64, mul_hh, t0_hi);
    // Lastly, extract the high 32 bits of t1 and add to t2.
    let t1_hi = map2!(_mm256_srli_epi64::<32>, t1);
    let res_hi = map2!(_mm256_add_epi64, t2, t1_hi);

    // Form res_lo by combining the low half of mul_ll with the low half of t1 (shifted into high
    // position).
    let t1_lo = {
        let t1_ps = map2!(_mm256_castsi256_ps, t1);
        let t1_lo_ps = map2!(_mm256_moveldup_ps, t1_ps);
        map2!(_mm256_castps_si256, t1_lo_ps)
    };
    let res_lo = map2!(_mm256_blend_epi32::<0xaa>, mul_ll, t1_lo);

    (
        (res_lo.0, res_lo.1, [z0_lo, z1_lo, z2_lo, z3_lo]),
        (res_hi.0, res_hi.1, [z0_hi, z1_hi, z2_hi, z3_hi])
    )
}

/// Addition, where the second operand is `0 <= y < 0xffffffff00000001`.
#[inline(always)]
unsafe fn add_small(
    x_s: (__m256i, __m256i),
    y: (__m256i, __m256i),
) -> (__m256i, __m256i) {
    let res_wrapped_s = map2!(_mm256_add_epi64, x_s, y);
    let mask = map2!(_mm256_cmpgt_epi32, x_s, res_wrapped_s);
    let wrapback_amt = map2!(_mm256_srli_epi64::<32>, mask); // EPSILON if overflowed else 0.
    let res_s = map2!(_mm256_add_epi64, res_wrapped_s, wrapback_amt);
    res_s
}

#[inline(always)]
unsafe fn maybe_adj_sub(res_wrapped_s: __m256i, mask: __m256i) -> __m256i {
    // The subtraction is very unlikely to overflow so we're best off branching.
    // The even u32s in `mask` are meaningless, so we want to ignore them. `_mm256_testz_pd`
    // branches depending on the sign bit of double-precision (64-bit) floats. Bit cast `mask` to
    // floating-point (this is free).
    let mask_pd = _mm256_castsi256_pd(mask);
    // `_mm256_testz_pd(mask_pd, mask_pd) == 1` iff all sign bits are 0, meaning that underflow
    // did not occur for any of the vector elements.
    if _mm256_testz_pd(mask_pd, mask_pd) == 1 {
        res_wrapped_s
    } else {
        branch_hint();
        // Highly unlikely: underflow did occur. Find adjustment per element and apply it.
        let adj_amount = _mm256_srli_epi64::<32>(mask); // EPSILON if underflow.
        _mm256_sub_epi64(res_wrapped_s, adj_amount)
    }
}

/// Addition, where the second operand is much smaller than `0xffffffff00000001`.
#[inline(always)]
unsafe fn sub_tiny(
    x_s: (__m256i, __m256i),
    y: (__m256i, __m256i),
) -> (__m256i, __m256i) {
    let res_wrapped_s = map2!(_mm256_sub_epi64, x_s, y);
    let mask = map2!(_mm256_cmpgt_epi32, res_wrapped_s, x_s);
    let res_s = map2!(maybe_adj_sub, res_wrapped_s, mask);
    res_s
}

#[inline(always)]
unsafe fn reduce3(
    (lo0, hi0): ((__m256i, __m256i, [u64; 4]), (__m256i, __m256i, [u64; 4])),
) -> (__m256i, __m256i, [u64; 4]) {
    let (a0, e0) = lo0.2[0].overflowing_add(lo0.2[0] << 32);
    let (a1, e1) = lo0.2[1].overflowing_add(lo0.2[1] << 32);
    let (a2, e2) = lo0.2[2].overflowing_add(lo0.2[2] << 32);
    let (a3, e3) = lo0.2[3].overflowing_add(lo0.2[3] << 32);

    let sign_bit = _mm256_set1_epi64x(i64::MIN);
    let epsilon = _mm256_set1_epi64x(0xffffffff);
    let lo0_s = map2!(_mm256_xor_si256, lo0, rep sign_bit);
    let hi_hi0 = map2!(_mm256_srli_epi64::<32>, hi0);

    let b0 = a0.wrapping_sub(a0 >> 32).wrapping_sub(e0 as u64);
    let b1 = a1.wrapping_sub(a1 >> 32).wrapping_sub(e1 as u64);
    let b2 = a2.wrapping_sub(a2 >> 32).wrapping_sub(e2 as u64);
    let b3 = a3.wrapping_sub(a3 >> 32).wrapping_sub(e3 as u64);

    let lo1_s = sub_tiny(lo0_s, hi_hi0);

    let (r0, c0) = hi0.2[0].overflowing_sub(b0);
    let (r1, c1) = hi0.2[1].overflowing_sub(b1);
    let (r2, c2) = hi0.2[2].overflowing_sub(b2);
    let (r3, c3) = hi0.2[3].overflowing_sub(b3);

    let t1 = map2!(_mm256_mul_epu32, hi0, rep epsilon);
    let lo2_s = add_small(lo1_s, t1);

    let res0 = r0.wrapping_sub(0u32.wrapping_sub(c0 as u32) as u64);
    let res1 = r1.wrapping_sub(0u32.wrapping_sub(c1 as u32) as u64);
    let res2 = r2.wrapping_sub(0u32.wrapping_sub(c2 as u32) as u64);
    let res3 = r3.wrapping_sub(0u32.wrapping_sub(c3 as u32) as u64);

    let lo2 = map2!(_mm256_xor_si256, lo2_s, rep sign_bit);
    (lo2.0, lo2.1, [res0, res1, res2, res3])

}

#[inline(always)]
unsafe fn mul_reduce(a: (__m256i, __m256i, [u64; 4]), b: (__m256i, __m256i, [u64; 4])) -> (__m256i, __m256i, [u64; 4]) {
    reduce3(mul3(a, b))
}


#[inline(always)]
unsafe fn square_reduce(state: (__m256i, __m256i, [u64; 4])) -> (__m256i, __m256i, [u64; 4]) {
    reduce3(square3(state))
}

#[inline(always)]
unsafe fn exp_acc(high: (__m256i, __m256i, [u64; 4]), low: (__m256i, __m256i, [u64; 4]), exp: usize) -> (__m256i, __m256i, [u64; 4]) {
    let mut result = high;
    for _ in 0..exp {
        result = square_reduce(result);
    }
    mul_reduce(result, low)
}

#[inline(always)]
unsafe fn add_constants(state: (__m256i, __m256i, [u64; 4]), const_s: (__m256i, __m256i, [u64; 4])) -> (__m256i, __m256i, [u64; 4]) {
    let res = map2!(_mm256_sub_epi64, state, const_s);
    let mask = map2!(_mm256_cmpgt_epi32, res, state);
    let res = map2!(maybe_adj_sub, res, mask);
    // TODO: this doesn't work without the top bit xor?
    (res.0, res.1, state.2)
}

#[inline(always)]
unsafe fn plonky2_sbox(state: (__m256i, __m256i, [u64; 4])) -> (__m256i, __m256i, [u64; 4]) {
    let state2 = square_reduce(state);
    let state4_unreduced = square3(state2);
    let state3_unreduced = mul3(state2, state);
    let state4 = reduce3(state4_unreduced);
    let state3 = reduce3(state3_unreduced);
    let state7_unreduced = mul3(state3, state4);
    let state7 = reduce3(state7_unreduced);
    state7
}

#[inline(always)]
unsafe fn plonky2_inv_sbox(state: (__m256i, __m256i, [u64; 4])) -> (__m256i, __m256i, [u64; 4]) {
    // compute base^10540996611094048183 using 72 multiplications per array element
    // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

    // compute base^10
    let mut t1 = square_reduce(state);

    // compute base^100
    let mut t2 = square_reduce(t1);

    // compute base^100100
    let t3 = exp_acc(t2, t2,3 );

    // compute base^100100100100
    let t4 = exp_acc(t3, t3, 6);

    // compute base^100100100100100100100100
    let t5 = exp_acc(t4, t4, 12);

    // compute base^100100100100100100100100100100
    let t6 = exp_acc(t5, t3, 6);

    // compute base^1001001001001001001001001001000100100100100100100100100100100
    let t7 = exp_acc(t6, t6, 31);

    // compute base^1001001001001001001001001001000110110110110110110110110110110111
    let a = square_reduce(square_reduce(mul_reduce( square_reduce(t7), t6)));
    let b = mul_reduce(t1, mul_reduce(t2, state));
    mul_reduce(a, b)
}

#[inline(always)]
unsafe fn avx2_load(state: &[u64; 12]) -> (__m256i, __m256i, [u64; 4]) {
    (
        _mm256_loadu_si256((&state[0..4]).as_ptr().cast::<__m256i>()),
        _mm256_loadu_si256((&state[4..8]).as_ptr().cast::<__m256i>()),
        state[8..12].try_into().unwrap()
    )
}

#[inline(always)]
unsafe fn avx2_store(buf: &mut [u64; 12], state: (__m256i, __m256i, [u64; 4])) {
    _mm256_storeu_si256((&mut buf[0..4]).as_mut_ptr().cast::<__m256i>(), state.0);
    _mm256_storeu_si256((&mut buf[4..8]).as_mut_ptr().cast::<__m256i>(), state.1);
    buf[8..12].copy_from_slice(&state.2);
}

#[inline(always)]
pub unsafe fn plonky2_apply_sbox(
    buffer: &mut [u64; 12],
    const_s: &[u64; 12],
) {
    let state = avx2_load(&buffer);
    let const_s = avx2_load(&const_s);
    let state_s = add_constants(state, const_s);
    let state = plonky2_sbox(state_s);
    avx2_store(buffer, state);
}

#[inline(always)]
pub unsafe fn plonky2_apply_inv_sbox(
    buffer: &mut [u64; 12],
    const_s: &[u64; 12],
) {
    let state = avx2_load(&buffer);
    let const_s = avx2_load(&const_s);
    let state_s = add_constants(state, const_s);
    let state = plonky2_inv_sbox(state_s);
    avx2_store(buffer, state);
}
