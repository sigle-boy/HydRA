
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

pub fn dqea_thresshare_one_phase(
    total_num: usize,
    thres_num: usize,
    srs: Srs,
    rho: Fr,
) -> (
    Vec<Fr>,
    Vec<Commitment>,
    Vec<G1Projective>,
    Vec<DensePolynomial<Fr>>,
) {
    let mut vecs: Vec<_> =
        (0..total_num)
            .into_par_iter()
            .enumerate()
            .map(
                |(idx, _)| {
                    let mut rng =
                        StdRng::seed_from_u64(
                            idx as u64,
                        );

                    let coeffs: Vec<_> =
                        (0..=thres_num)
                            .map(
                                |_| {
                                    rng.random_range(
                                        10011..255451,
                                    )
                                },
                            )
                            .collect();

                    poly_from_coeffs(
                        &coeffs,
                    )
                },
            )
            .collect();

    let x_i_vector =
        vecs
            .par_iter()
            .map(
                |vec| {
                    vec[0]
                },
            )
            .collect::<Vec<_>>();

    let comm_i_vector =
        vecs
            .par_iter()
            .map(
                |poly| {
                    commit(
                        &srs,
                        &poly,
                    )
                    .unwrap()
                },
            )
            .collect::<Vec<_>>();

    let y_i_vector =
        vecs
            .par_iter()
            .map(
                |x| {
                    G1Projective::generator()
                        * x[0]
                },
            )
            .collect::<Vec<_>>();

    let results: Vec<_> =
        (0..total_num)
            .into_par_iter()
            .map(
                |j| {
                    let value =
                        open(
                            &vecs[1],
                            Fr::from(
                                j as u32,
                            ),
                        );

                    let fy_small_val =
                        G1Projective::generator()
                            * value.0;

                    let w_val =
                        create_witness(
                            &srs,
                            &vecs[1],
                            2,
                            Fr::from(
                                j as u32,
                            ),
                            rho,
                        )
                        .unwrap();

                    (
                        value.clone(),
                        fy_small_val,
                        w_val,
                    )
                },
            )
            .collect();

    let (
        mut fy_big,
        mut fy_small,
        mut w,
    ) = (
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    for (
        value,
        fy_small_val,
        w_val,
    ) in results {
        fy_big.push(
            value,
        );

        fy_small.push(
            fy_small_val,
        );

        w.push(
            w_val,
        );
    }

    (
        x_i_vector,
        comm_i_vector,
        y_i_vector,
        vecs,
    )
}
