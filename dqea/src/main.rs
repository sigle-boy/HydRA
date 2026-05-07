use ark_bls12_381::{Fr};
use ark_ff::{ Zero};

use std::fs;

use std::time::{Duration, Instant};

use rayon::{prelude::*};

use dqea::{dqea_setup,dqea_thresshare_one_phase,dqea_quote_phase, dqea_thresshare_two_phase,dqea_compute_sharesandwitness,dqea_verify,dqea_prequote_phase,get_nizk_type2,verify_nizk_type2};
use dqea::triple::gen_beaver_triple_n_n;
use dqea::interpolation::{ith_lagrange_coefficient};


const THRESHORD: usize = 100;
const TOTAL_NUMBER: usize = 105;
const HEADER_LEN: usize = 48;
const REPORT_BODY_LEN: usize = 384;
const HEADER_REPORT_BODY_LEN: usize = HEADER_LEN + REPORT_BODY_LEN;


fn main () {
    println!("This is a test file.");
     println!("t: {}", THRESHORD);
    println!("n: {}", TOTAL_NUMBER);
    let i_value = Fr::from(2);
    let rho = Fr::from(11u64);
    let rng = &mut ark_std::test_rng();

   
    let quote = fs::read("quote.dat").expect("read error");
    println!("file: {:?}",quote);
    let header = &quote[0..HEADER_LEN];
    let report_body = &quote[HEADER_LEN..HEADER_REPORT_BODY_LEN];

    println!("header: {:?}", header);
    println!("report_body: {:?}", report_body);
    new_test();


}
