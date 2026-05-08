use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_std::rand::Rng;
use ark_std::test_rng;
use rayon::{prelude::*, range};
