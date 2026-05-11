
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

  let g = G1Projective::rand(rng).into_affine();
  let h = G2Projective::rand(rng).into_affine();
  let gamma = Fr::rand(rng);

  let mut gamma_g_powers = Vec::with_capacity(max_degree + 1);
  let mut cur = Fr::one();
  for _ in 0..=max_degree {
    gamma_g_powers.push(g.mul_bigint(cur.into_brgint()).into_affine());
    cur *= gamma;
  }

  let mut gamma_h_powers = Vec::with_capacity(max_degree + 1);
  let mut cur2 = Fr::one();
  for _ in 0..=max_degree {
    gamma_h_powers.push(h.mul_bigint(cur2.into_bigint()).into_affine());
    cur2 *= gamma;
  }

  let gamma_h = h.mul_bigint(gamma.into_bigint()).into_affine();
  println!("TEST");
  Ok(Srs {
    g,
    h,
    gamma_g_powers,
    gamma_h_powers,
    max_degree,
    gamma_secret_for_demo_only: gamma,
  })
  
}

pub fn commit(srs: &Srs, poly: &Poly) -> Result<Commitment, PcError> {
    let degree = poly.degree();
    if degree > srs.max_degree {
        return Err(PcError::DegreeTooLarge {
            degree,
            max_degree: srs.max_degree,
        });
    }

    let mut acc = G1Projective::zero();
    for (l, coeff) in poly.coeffs.iter().enumerate() {
        if coeff.is_zero() {
            continue;
        }
        let basis = srs.gamma_g_powers[l];
        acc += basis.mul_bigint(coeff.into_bigint());
    }

    Ok(Commitment(acc.into_affine()))
}

   
