
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, Polynomial
};
use ark_std::rand::{Rng, RngCore};
use std::fmt::{Display, Formatter};
use rayon::{prelude::*};
type Poly = DensePolynomial<Fr>;
type GT = <Bls12_381 as Pairing>::TargetField;

use rayon::{prelude::*, range};
