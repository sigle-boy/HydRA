use std::fs;
use ark_ff::PrimeField;
use ark_bls12_381:: Fr;
use arkworks_utils::{
		bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
	};
use arkworks_native_gadgets::poseidon::{
		sbox::PoseidonSbox,  Poseidon, PoseidonParameters,
	};

pub fn PoseidonSetup(curve: Curve, exp: i8, width: u8) -> Poseidon<Fr>{
let para = setup_params(curve, exp, width);
}
