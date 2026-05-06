
pub mod distributed_ecdsa;
pub mod interpolation;
pub mod triple;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing,  CurveGroup, PrimeGroup};
use ark_ff::{Field,  UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial
};
use ark_std::rand::{ RngCore};
use sha2::{Digest, Sha256,};

use num_bigint::BigUint;
type Poly = DensePolynomial<Fr>;
type GT = <Bls12_381 as Pairing>::TargetField;

use distributed_ecdsa::{Commitment, Share, Srs, Witness, commit, create_witness, open, poly_from_coeffs, setup, verify_aggregated};
use interpolation::{ith_lagrange_coefficient};
use triple::{AdditiveShares, BeaverTripleShares, beaver_multiply_n_n, gen_beaver_triple_n_n, share_secret_n_n};
use std::time::{Duration, Instant};

use rayon::{prelude::*};
use rand::{RngExt, SeedableRng};
use rand::rngs::StdRng;

pub fn dqea_setup<R: RngCore>(
    thresh_num: usize,
    rng: &mut R,
) -> Srs {
    let srs = setup(
        thresh_num,
        rng,
    )
    .unwrap();

    srs
}
