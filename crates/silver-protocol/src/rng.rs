//! The operating system's random number generator, as the code draws keys,
//! nonces and padding from it.
//!
//! rand 0.10 offers it as [`SysRng`], whose reads may fail. [`OsRng`] reads
//! it the way rand 0.8's `OsRng` did, which this code was written against: a
//! failure to get randomness from the operating system is a panic, never a
//! value to carry on with.

use core::convert::Infallible;

use rand::Rng;
use rand::rand_core::{TryCryptoRng, TryRng, UnwrapErr};
use rand::rngs::SysRng;

/// The operating system's generator; panics if the system cannot supply
/// randomness.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(UnwrapErr(SysRng).next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(UnwrapErr(SysRng).next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        UnwrapErr(SysRng).fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::CryptoRng;

    fn crypto(_: &mut impl CryptoRng) {}

    #[test]
    fn it_is_a_cryptographic_generator_and_draws() {
        crypto(&mut OsRng);
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        OsRng.fill_bytes(&mut a);
        OsRng.fill_bytes(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
