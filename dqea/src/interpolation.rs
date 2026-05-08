use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField, Zero};
use rayon::{prelude::*};
#[derive(Debug)]
pub enum LagrangeError {
    EmptyInput,
    IndexOutOfRange,
    DuplicatePoint,
}
pub fn ith_lagrange_coefficient<F: PrimeField>(
    xs: &[F],
    i: usize,
    tau: F,
) -> Result<F, LagrangeError> {
    if xs.is_empty() {
        return Err(LagrangeError::EmptyInput);
    }
    if i >= xs.len() {
        return Err(LagrangeError::IndexOutOfRange);
    }

    let x_i = xs[i];
    let mut num = F::from(1u64);
    let mut den = F::from(1u64);

    for (j, x_j) in xs.iter().enumerate() {
        if j == i {
            continue;
        }
        if *x_j == x_i {
            return Err(LagrangeError::DuplicatePoint);
        }
        num *= tau - x_j;
        den *= x_i - x_j;
    }

    let den_inv = den.inverse().ok_or(LagrangeError::DuplicatePoint)?;
    Ok(num * den_inv)
}
