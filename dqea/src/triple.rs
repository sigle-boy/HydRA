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

/// 生成一个随机秘密的 (n,n) additive sharing
///
/// 方法：前 n-1 份随机，最后一份补齐，使总和等于 secret。
pub fn share_secret_n_n<F: Field, R: Rng>(
    secret: F,
    thres_num: usize,
    rng: &mut R,
) -> AdditiveShares<F> {
    assert!(thres_num >= 1, "n must be at least 1");

    let mut shares = Vec::with_capacity(thres_num);
    let mut sum = F::zero();

    for _ in 0..(thres_num - 1) {
        let s = F::rand(rng);
        shares.push(s);
        sum += s;
    }

    shares.push(secret - sum);

    AdditiveShares { shares }
}

/// trusted dealer 生成一个 Beaver triple，并把 a,b,c 各自拆成 (n,n) shares
pub fn gen_beaver_triple_n_n<F: Field, R: Rng>(
    thres_num: usize,
    rng: &mut R,
) -> BeaverTripleShares<F> {
    let a = F::rand(rng);
    let b = F::rand(rng);
    let c = a * b;

    BeaverTripleShares {
        a: share_secret_n_n(a, thres_num, rng),
        b: share_secret_n_n(b, thres_num, rng),
        c: share_secret_n_n(c, thres_num, rng),
    }
}
