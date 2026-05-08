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

/// 用 Beaver triple 计算 [x] * [y] = [z]
///
/// 输入：
/// - x_shares: x 的 additive shares
/// - y_shares: y 的 additive shares
/// - triple:   Beaver triple shares
///
/// 输出：
/// - z_shares，使得 reconstruct(z_shares) = x * y
///
/// 协议：
/// 1) 每方本地计算 d_i = x_i - a_i, e_i = y_i - b_i
/// 2) 公开重构 d = sum d_i, e = sum e_i
/// 3) 每方输出 z_i = c_i + d*b_i + e*a_i
/// 4) 指定一个方（这里取第 0 个）再加上 d*e
pub fn beaver_multiply_n_n<F: Field>(
    x_shares: &AdditiveShares<F>,
    y_shares: &AdditiveShares<F>,
    triple: &BeaverTripleShares<F>,
) -> AdditiveShares<F> {
    let n = x_shares.len();
    assert_eq!(y_shares.len(), n);
    assert_eq!(triple.a.len(), n);
    assert_eq!(triple.b.len(), n);
    assert_eq!(triple.c.len(), n);

    // d_i = x_i - a_i, e_i = y_i - b_i
    let d_shares: Vec<F> = (0..n).into_par_iter()
        .map(|i| x_shares.shares[i] - triple.a.shares[i])
        .collect();

    let e_shares: Vec<F> = (0..n).into_par_iter()
        .map(|i| y_shares.shares[i] - triple.b.shares[i])
        .collect();

    // 公开重构
    let d = d_shares.iter().copied().fold(F::zero(), |acc, x| acc + x);
    let e = e_shares.iter().copied().fold(F::zero(), |acc, x| acc + x);

    // z_i = c_i + d*b_i + e*a_i
   let mut z: Vec<F> = triple.c.shares
    .par_iter()
    .zip(triple.b.shares.par_iter())
    .zip(triple.a.shares.par_iter())
    .map(|((&c, &b), &a)| c + d * b + e * a)
    .collect();

    z[0] += d * e;

 

    AdditiveShares { shares: z }
}
