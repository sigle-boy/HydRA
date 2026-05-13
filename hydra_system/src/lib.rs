pub mod poseidon;
pub mod zkcircuit;
pub mod shurbstree;

pub fn GenerateSingleDeviceInfor() -> (Fr, Fr)  {

    let hasher = PoseidonSetup(Curve::Bls381, 5, 3);

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("获取系统时间失败"); 
    let period = Duration::from_secs(8640000 as u64); 
    let signing_key = SigningKey::<Secp256k1>::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let measure = fs::read_to_string("example.txt").expect("文件读取错误");

    let sk = Fr::from(BigUint::from_bytes_be(&signing_key.to_bytes()[..]));
    let pk = Fr::from(BigUint::from_bytes_be(verifying_key.to_encoded_point(true).as_bytes()));
    let ar = Fr::from(BigUint::from_bytes_be(measure.as_bytes()));
    let times = Fr::from(timestamp.as_secs());
    let peri = Fr::from(period.as_secs());

    let c = hasher.hash(&[ar, sk][..]).unwrap();
	let leaf = hasher.hash(&[c, pk][..]).unwrap();
	let output_1 = hasher.hash(&[pk, ar][..]).unwrap();
	let output_2 = hasher.hash(&[output_1, sk][..]).unwrap();
	let output_3 = hasher.hash(&[output_2, times][..]).unwrap();
	let output = hasher.hash(&[output_3, peri][..]).unwrap();

    println!("pk: {}", pk);
    println!("sk: {}", sk);
    println!("ar: {}", ar);
    println!("times: {}", times);
    println!("peri: {}", peri);

    (leaf, output)
}

pub fn GenerateDeviceKey() -> (SigningKey<Secp256k1>, VerifyingKey<Secp256k1>)   {

    let signing_key: SigningKey<Secp256k1> = SigningKey::<Secp256k1>::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    (signing_key, verifying_key)
}
