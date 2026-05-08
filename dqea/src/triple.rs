use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_std::rand::Rng;
use ark_std::test_rng;
use rayon::{prelude::*, range};

#[derive(Clone, Debug)]
pub struct AdditiveShares<F: Field> {
    pub shares: Vec<F>,
}

impl<F: Field> AdditiveShares<F> {
    /// 重构秘密
    pub fn reconstruct(&self) -> F {
        self.shares.iter().copied().fold(F::zero(), |acc, x| acc + x)
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }
}

/// Beaver triple 的 shares: [a_i], [b_i], [c_i], with c = a*b
#[derive(Clone, Debug)]
pub struct BeaverTripleShares<F: Field> {
    pub a: AdditiveShares<F>,
    pub b: AdditiveShares<F>,
    pub c: AdditiveShares<F>,
}
