use ark_groth16::Groth16;
use ark_crypto_primitives::SNARK;
use ark_bls12_381::{Bls12_381, Fr};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use std::time::Instant;

use arkworks_native_gadgets::poseidon::FieldHasher;

use ark_std::UniformRand;
use smart_tree::poseidon::PoseidonSetup;
use smart_tree::zkcircuit::TestCircuit;
use smart_tree::shurbstree::{BuildShrubs,Build_Static_Shrubs, Find_Shrubs_Path};
type GrothSetup = Groth16<Bls12_381>;
type PoseidonC<'a> = TestCircuit<'a, Fr, PoseidonGadget<Fr>>;
const LEN: usize = 10;

fn main() {
    println!("Hello, world!");
    let mut b_tree = Vec::new();
    for i in 0..2_i32.pow(LEN as u32) {
         b_tree.push(Fr::rand(rng));
}
    
let mut root = vec![];

b_tree[223] = leaf;
	
	Build_Static_Shrubs(&mut root, &b_tree, hasher.clone());

	println!("root length: {}", root.len());
let hasher = PoseidonSetup(Curve::Bls381, 5, 3);
	let pk = Fr::rand(rng);
	let sk = Fr::rand(rng);
	let time = Fr::rand(rng);
	let period = Fr::rand(rng);
	let ar = Fr::rand(rng);


	let c = hasher.hash(&[ar, sk][..]).unwrap();
	let leaf = hasher.hash(&[c, pk][..]).unwrap();
	let output_1 = hasher.hash(&[pk, ar][..]).unwrap();
	let output_2 = hasher.hash(&[output_1, sk][..]).unwrap();
	let output_3 = hasher.hash(&[output_2, time][..]).unwrap();
	let output = hasher.hash(&[output_3, period][..]).unwrap();


b_tree[223] = leaf;
	
	Build_Static_Shrubs(&mut root, &b_tree, hasher.clone());

	println!("root length: {}", root.len());
    
}

let circuit = PoseidonC::new(pk, sk,ar, time,period,output, root[LEN],&path, &tag, hasher);

	let (pkk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

let start = Instant::now();

	let proof = GrothSetup::prove(&pkk, circuit, rng).unwrap();
	let duration = start.elapsed();

println!("设备的公钥信息：{}",pk);
	println!("设备的私钥信息：{}",sk);
	println!("设备的创建时间：{}",time);
	println!("设备的有效期：{}",period);
	println!("设备被度量的内存信息：{}",ar);
	println!("Groth proof time: {:?}", duration);

let start = Instant::now();
	let res = GrothSetup::verify(&vk, &[pk, root[LEN], output, time, period][..], &proof).unwrap();
	let duration = start.elapsed();
