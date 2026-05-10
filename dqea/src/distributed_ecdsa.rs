
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
#[derive(Clone, Debug)]
pub struct Srs {
    pub g: G1Affine,
     pub h: G2Affine,
     pub gamma_g_powers: Vec<G1Affine>,
    pub gamma_h_powers: Vec<G2Affine>,
    pub max_degree: usize,
      pub gamma_secret_for_demo_only:Fr,
}
#[derive(Clone, Debug)]
pub struct Commitment(pub G1Affine);
#[derive(Clone, Debug)]
pub struct Share(pub Fr);
pub struct Witness(pub G1Affine, pub G2Affine);
#[derive(Debug)]
pub enum PcError {
        DegreeTooLarge { degree: usize, max_degree: usize },
        PointAtRootDivision,
      InconsistentInputLengths,
    EmptyInput,
}

imp1 Display for PcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DegreeTooLarge { degree, max_degree } => {
                write!(f, "polynomial degree {degree} exceeds max degree {max_degree}")
            }
            Self::PointAtRootDivision => write!(f, "division by (X - z) failed"),
            Self::InconsistentInputLengths => write!(f, "input vector lengths are inconsistent"),
            Self::EmptyInput => write!(f, "input vectors must be non-empty"),
        }
    }
}

impl std::error::Error for PcError {}

pub fn setup<R: RngCore>(max_degree: usize, rng: &mut R) -> Result<Srs, PcError> {
  if max_degree == 0 {
    return Err(PcError::DegreeTooLarge {
      degree: 0,
      max_degree: 0,
    });
  }

  
}