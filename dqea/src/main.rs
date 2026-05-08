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


fn new_test() {
    let i_value = Fr::from(2);
    let rho = Fr::from(11u64);
    let rng = &mut ark_std::test_rng();
    let mut time = Vec::new();
    //阶段1
    let start = Instant::now();
    let srs = dqea_setup(THRESHORD, rng);
    let duration1 = start.elapsed();
    println!("Setup Phase Time elapsed: {:?}", duration1);
    time.push(duration1);


        let start =
    Instant::now();

    let (
            x_i_vector,
            comm_i_vector,
            y_i_vector,
            vecs,
        ) =
            dqea_thresshare_one_phase(
                TOTAL_NUMBER,
                THRESHORD,
                srs.clone(),
                rho,
            );

    let duration2 =
        start.elapsed();

    let (
        shares,
        witnesses,
    ) =
        dqea_compute_sharesandwitness(
            vecs.clone(),
            srs.clone(),
            rho,
            i_value,
        );

        let start =
            Instant::now();

        let (
            u_i_small_vector,
            vk,
        ) =
            dqea_thresshare_two_phase(
                x_i_vector.clone(),
                comm_i_vector,
                y_i_vector.clone(),
                srs.clone(),
                rho,
                vecs.clone(),
                shares,
                witnesses,
                TOTAL_NUMBER,
            );

        let duration3 =
            start.elapsed();

        println!(
            "ThresShare Phase Time elapsed: {:?}",
            duration2 + duration3,
        );

        time.push(
            duration2,
        );

        time.push(
            duration3,
        );

        let mut base_element =
            Vec::new();

        for i in 0..THRESHORD + 1 {
            base_element.push(
                Fr::from(
                    i as i32,
                ),
            );
        }

        let triple =
            gen_beaver_triple_n_n(
                THRESHORD + 1,
                rng,
            );

        let lambda_i_vector: Vec<_> =
            (0..THRESHORD + 1)
                .into_par_iter()
                .map(
                    |index| {
                        ith_lagrange_coefficient(
                            &base_element,
                            index,
                            Fr::zero(),
                        )
                        .unwrap()
                    },
                )
                .collect();


        // 阶段3
        let start =
            Instant::now();

        let (
            k_i_vector,
            w_i_vector,
            fy_i_vector,
            pi_i_two_vector,
            V_i_vector,
        ) =
            dqea_prequote_phase(
                triple,
                x_i_vector,
                y_i_vector.clone(),
                lambda_i_vector,
                u_i_small_vector,
                rng,
                THRESHORD,
            );

        let duration4 =
            start.elapsed();

        println!(
            "PreQuote Phase Time elapsed: {:?}",
            duration4,
        );

        time.push(
            duration4,
        );


        let report_m =
            "This is a report"
                .as_bytes();

        let header_phi =
            "This is a header message"
                .as_bytes();


        // 阶段4
        let start =
            Instant::now();

        let (
            s_i_vector,
            Theta_new,
            r_new,
            hash_message_to_field,
            R_new,
        ) =
            dqea_quote_phase(
                vk,
                y_i_vector,
                fy_i_vector,
                pi_i_two_vector,
                V_i_vector,
                k_i_vector,
                w_i_vector,
                report_m,
                header_phi,
                THRESHORD,
            );

        let duration5 =
            start.elapsed();

        println!(
            "Quote Phase Time elapsed: {:?}",
            duration5,
        );

        time.push(
            duration5,
        );


        // 阶段5
        let start =
            Instant::now();

        let p_iii =
            get_nizk_type2(
                s_i_vector.clone(),
                R_new,
            );

        verify_nizk_type2(
            R_new,
            r_new,
            vk,
            p_iii,
            hash_message_to_field,
            Theta_new,
        );

        let s =
            Theta_new
                * hash_message_to_field
                + s_i_vector
                    .iter()
                    .sum::<Fr>();

        let sig =
            (
                r_new,
                s,
            );

        let duration6 =
            start.elapsed();

        println!(
            "Combine Phase Time elapsed: {:?}",
            duration6,
        );

        time.push(
            duration6,
        );


        // 阶段6
        let start =
            Instant::now();

        dqea_verify(
            hash_message_to_field,
            vk,
            sig,
        );

        let duration7 =
            start.elapsed();

        println!(
            "Verify Phase Time elapsed: {:?}",
            duration7,
        );

        println!(
            "Total time : {:?}",
            time
                .iter()
                .sum::<Duration>(),
        );
}
