pub mod poseidon;
pub mod zkcircuit;
pub mod shurbstree;

use ark_bls12_381::{Bls12_381, Fr as BlsScalar};
use shurbstree::{find_shrubs_path,find_interval_index,insert_shrubs_tree,exponents_of_two};
use arkworks_native_gadgets::poseidon::{Poseidon,FieldHasher};
use rand_core::OsRng;
use ecdsa::{SigningKey, VerifyingKey};
use k256::Secp256k1;
use num_bigint::BigUint;
use std::fs;
use std::time::{Duration,SystemTime, UNIX_EPOCH};
use ark_std::rand::rngs::StdRng;
use ark_std::UniformRand;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature,
};
use ark_groth16::{VerifyingKey as ArkVerifyingKey,Proof};
use ark_serialize::{CanonicalSerialize, SerializationError};

use k256::elliptic_curve::sec1::ToEncodedPoint;



#[derive(Debug)]
pub struct EvidenceReply {
    pub proof: Proof<Bls12_381>,
    pub vk:  ArkVerifyingKey<Bls12_381>,
    pub sig:   Signature,
    pub pk:  VerifyingKey<Secp256k1>,
    pub timestamp:BlsScalar,
    pub period: BlsScalar,
    pub authorized_infor: BlsScalar,

}

impl EvidenceReply {
    pub fn new(proof: Proof<Bls12_381>,vk: ArkVerifyingKey<Bls12_381>, dev_config: &DeviceConfigInfor  ) -> EvidenceReply {
            EvidenceReply{
                proof,
                vk,
                sig: dev_config.signature.unwrap(),
                pk: dev_config.verifying_key,
                timestamp: dev_config.timestamp,
                period: dev_config.period,
                authorized_infor: dev_config.authorized_infor,
            }

    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        self.proof.serialize_uncompressed(&mut bytes).unwrap();
        self.vk.serialize_uncompressed(&mut bytes).unwrap();

        bytes.extend_from_slice(self.sig.to_bytes().as_slice());
        bytes.extend_from_slice(self.pk.to_encoded_point(true).as_bytes());

        self.timestamp.serialize_uncompressed(&mut bytes).unwrap();
        self.period.serialize_uncompressed(&mut bytes).unwrap();
        self.authorized_infor.serialize_uncompressed(&mut bytes).unwrap();

        bytes
    }

    pub fn to_signing_bytes_all_fields(&self) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::new();

        let proof_bytes = serialize_ark(&self.proof)?;
        append_field(&mut out, &b"proof"[..], &proof_bytes);

        let vk_bytes = serialize_ark(&self.vk)?;
        append_field(&mut out, &b"vk"[..], &vk_bytes);

        let sig_der = self.sig.to_der();
        append_field(&mut out, &b"sig"[..], sig_der.as_bytes());

        let pk_encoded = self.pk.to_encoded_point(true);
        append_field(&mut out, &b"pk"[..], pk_encoded.as_bytes());

        let timestamp_bytes = serialize_ark(&self.timestamp)?;
        append_field(&mut out, &b"timestamp"[..], &timestamp_bytes);

        let period_bytes = serialize_ark(&self.period)?;
        append_field(&mut out, &b"period"[..], &period_bytes);

        let authorized_infor_bytes = serialize_ark(&self.authorized_infor)?;
        append_field(&mut out, &b"authorized_infor"[..], &authorized_infor_bytes);

        Ok(out)
    }

}

fn append_field(out: &mut Vec<u8>, field_name: &[u8], field_data: &[u8]) {
    out.extend_from_slice(&(field_name.len() as u64).to_be_bytes());
    out.extend_from_slice(field_name);

    out.extend_from_slice(&(field_data.len() as u64).to_be_bytes());
    out.extend_from_slice(field_data);
}

fn serialize_ark<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug)]
pub struct DeviceClientInfor {
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub measured_value: String,
    pub merkle_leaf: BlsScalar,
    pub evidence: Vec<u8>,
}
impl DeviceClientInfor  {
    pub fn new(vk: VerifyingKey<Secp256k1>,leaf: BlsScalar) -> DeviceClientInfor {
        let measure = fs::read_to_string("example.txt").expect("度量信息读取错误");
        DeviceClientInfor {
            verifying_key: vk,
            merkle_leaf: leaf,
            measured_value: measure,
            evidence: vec![32,35,35],
        }
    }
}



pub fn find_device_shrubs_path_tag(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    leaf: BlsScalar,
    hasher: &Poseidon<BlsScalar>,
) -> (Option<Vec<BlsScalar>>, Option<Vec<bool>>) {
    match find_interval_index(&leaves, leaf) {
        Some((vect, index)) => {
            let inx = 0;

            match find_shrubs_path(&root, &vect, inx, index, hasher) {
                Some((path, tag)) => {
                    // for i in path.iter() {
                    //     println!("path: {}", i);
                    // }

                    (Some(path), Some(tag))
                }

                None => {
                    (None, None)
                }
            }
        }

        None => {
            println!("110");
            (None, None)
        }
    }
}

pub fn verifier_compute_sig(verifier_key: &KeyInfor, device_time: &ResponseDeviceInfor) -> Signature {
    let mut msg = Vec::new();
    msg.extend_from_slice(device_time.verifying_key.to_encoded_point(true).as_bytes());
    msg.extend_from_slice(&device_time.timestamp.as_secs().to_be_bytes());
    msg.extend_from_slice(&device_time.period.as_secs().to_be_bytes());
    let sig = verifier_key.signing_key.sign(msg.as_slice());
    sig 
}

#[derive(Debug)]
pub struct DeviceConfigInfor {
    pub signing_key: SigningKey<Secp256k1>,
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub measured_value: BlsScalar,
    pub timestamp: BlsScalar,
    pub period: BlsScalar,
    pub merkle_leaf: BlsScalar,
    pub merkle_path: Option<Vec<BlsScalar>>,
    pub merkle_tag: Option<Vec<bool>>,
    pub authorized_infor: BlsScalar,
    pub signature: Option<Signature>,
}

impl DeviceConfigInfor {
    pub fn gen_test_infor(
        mut rng: &mut StdRng,
        hasher: &Poseidon<BlsScalar>,
    ) -> DeviceConfigInfor {

        let pk = BlsScalar::rand(&mut rng);
        let sk = BlsScalar::rand(&mut rng);
        let time = BlsScalar::rand(&mut rng);
        let period = BlsScalar::rand(&mut rng);
        let ar = BlsScalar::rand(&mut rng);

        let c = hasher.hash(&[ar, sk][..]).unwrap();
        let leaf = hasher.hash(&[c, pk][..]).unwrap();
        let output_1 = hasher.hash(&[pk, ar][..]).unwrap();
        let output_2 = hasher.hash(&[output_1, time][..]).unwrap();
        let output = hasher.hash(&[output_2, period][..]).unwrap();

        DeviceConfigInfor {
            signing_key: sk,
            verifying_key: pk,
            measured_value: ar,
            timestamp: time,
            period: period,
            merkle_leaf: leaf,
            authorized_infor: output,
        }
    }

    pub fn gen_public_inputs(&self, root: &[BlsScalar]) -> Vec<BlsScalar> {
        let mut public_inputs = vec![];
        public_inputs.push(BlsScalar::from(BigUint::from_bytes_be(self.verifying_key.to_encoded_point(true).as_bytes()))); 
        public_inputs.extend_from_slice(&root);
        public_inputs.push(self.authorized_infor);
        public_inputs.push(self.timestamp);
        public_inputs.push(self.period);

        public_inputs
    }

    pub fn new(
        dev_key: KeyInfor,
        dev_cli: DeviceClientInfor,
        dec_res: ResponseDeviceInfor,
        hasher: &Poseidon<BlsScalar>,
    ) -> DeviceConfigInfor {
        
        let sk = BlsScalar::from(BigUint::from_bytes_be(&dev_key.signing_key.to_bytes()[..]));
        let pk = BlsScalar::from(BigUint::from_bytes_be(
            &dev_key.verifying_key.to_encoded_point(true).as_bytes(),
        ));
        let ar = BlsScalar::from(BigUint::from_bytes_be(dev_cli.measured_value.as_bytes()));
        let time = BlsScalar::from(dec_res.timestamp.as_secs());
        let peri = BlsScalar::from(dec_res.period.as_secs());
        let leaf = dev_cli.merkle_leaf;
        let output = generate_verifier_authoried_infor(ar, pk, time, peri, hasher);

        DeviceConfigInfor {
            signing_key: dev_key.signing_key,
            verifying_key: dev_key.verifying_key,
            measured_value: ar,
            timestamp: time,
            period: peri,
            merkle_leaf: leaf,
            authorized_infor: output,
            merkle_path: dec_res.shrubs_path,
            merkle_tag: dec_res.shrubs_tag,
            signature: dec_res.sig,
        }
    }
}

pub struct  KeyInfor {
    pub signing_key: SigningKey<Secp256k1>,
    pub verifying_key: VerifyingKey<Secp256k1>,
}

impl KeyInfor {
    pub fn new() -> Self{
        let signing_key: SigningKey<Secp256k1> = SigningKey::<Secp256k1>::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key
        }
    }
}


pub fn generate_device_merkle_leaf(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let measure = fs::read_to_string("example.txt").expect("度量信息读取错误");
    let sk = BlsScalar::from(BigUint::from_bytes_be(&device_key.signing_key.to_bytes()[..]));
    let pk = BlsScalar::from(BigUint::from_bytes_be(
            &device_key.verifying_key.to_encoded_point(true).as_bytes(),
        ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(measure.as_bytes()));

    let c = hasher.hash(&[ar, sk][..]).unwrap();
    let leaf = hasher.hash(&[c, pk][..]).unwrap();

    leaf
}
pub struct ResponseDeviceInfor {
    pub timestamp: Duration,
    pub period: Duration,
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub sig : Option<Signature>,
    pub shrubs_path: Option<Vec<BlsScalar>>,
    pub shrubs_tag: Option<Vec<bool>>,
}

impl ResponseDeviceInfor {
    pub fn new(pk: VerifyingKey<Secp256k1>) ->  ResponseDeviceInfor {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("获取系统时间失败");
        let period = Duration::from_secs(8640000 as u64);
         ResponseDeviceInfor {
            timestamp,
            period, 
            verifying_key:pk,
            sig: None,
            shrubs_path: None,
            shrubs_tag: None,
         }
    }
    pub fn set_signature(&mut self,sig: &Signature) {
        self.sig = Some(*sig);
    }

    pub fn set_shrubs_path_and_tag(&mut self, path: Vec<BlsScalar>, tag: Vec<bool> ) {
            self.shrubs_path = Some(path);
            self.shrubs_tag = Some(tag);
    }

}

pub fn generate_device_authoried_infor(
    devices_infor: &DeviceClientInfor,
    devices_time: &ResponseDeviceInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {

    let pk = BlsScalar::from(BigUint::from_bytes_be(
            devices_infor.verifying_key.to_encoded_point(true).as_bytes(),
        ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(devices_infor.measured_value.as_bytes()));
    let time = BlsScalar::from(devices_time.timestamp.as_secs());
    let peri = BlsScalar::from(devices_time.period.as_secs());

    let temp_1 = hasher.hash(&[pk, ar][..]).unwrap();
    let temp_2 = hasher.hash(&[temp_1, time][..]).unwrap();
    let output = hasher.hash(&[temp_2, peri][..]).unwrap();

    output
}

pub fn generate_verifier_authoried_infor(
    ar: BlsScalar,
    pk: BlsScalar,
    time: BlsScalar,
    peri: BlsScalar,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let temp_1 = hasher.hash(&[pk, ar][..]).unwrap();
    let temp_2 = hasher.hash(&[temp_1, time][..]).unwrap();
    let output = hasher.hash(&[temp_2, peri][..]).unwrap();

    output
}

pub fn insert_batch_devices(
    mut root: &mut Vec<BlsScalar>,
    old_leaves: &[BlsScalar],
    new_leaves: &mut Vec<BlsScalar>,
    hasher: &Poseidon<BlsScalar>,
) {
    let k: isize = -1;
    let ll: usize = 0;

    let exps = exponents_of_two(old_leaves.len());

    if exps[0] == 0 {
        let mut n_leaf = Vec::with_capacity(new_leaves.len() + 1);
        n_leaf.push(root[0]);
        n_leaf.append(new_leaves);

        insert_shrubs_tree(&mut root, &n_leaf, k, &exps, ll + 1, &hasher);
    } else {
        insert_shrubs_tree(&mut root, &new_leaves, k, &exps, ll, &hasher);
    }
}


#[derive(Debug)]
pub struct PublicContext {
    pub root: Vec<BlsScalar>,
    pub verifier_pk: VerifyingKey<Secp256k1>,
}

fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_exact<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    cursor.read_exact(&mut buf).context("读取二进制字段失败")?;
    Ok(buf)
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    Ok(u64::from_be_bytes(read_exact::<8>(cursor)?))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    Ok(u32::from_be_bytes(read_exact::<4>(cursor)?))
}

fn read_len_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = read_u64(cursor)? as usize;
    let mut bytes = vec![0u8; len];
    cursor.read_exact(&mut bytes).context("读取变长二进制字段失败")?;
    Ok(bytes)
}

fn append_string(out: &mut Vec<u8>, value: &str) {
    append_len_bytes(out, value.as_bytes());
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    String::from_utf8(read_len_bytes(cursor)?).context("解析 UTF-8 字符串失败")
}

fn append_duration(out: &mut Vec<u8>, value: Duration) {
    out.extend_from_slice(&value.as_secs().to_be_bytes());
    out.extend_from_slice(&value.subsec_nanos().to_be_bytes());
}

fn read_duration(cursor: &mut Cursor<&[u8]>) -> Result<Duration> {
    let secs = read_u64(cursor)?;
    let nanos = read_u32(cursor)?;
    Ok(Duration::new(secs, nanos))
}

fn encode_scalar(value: &BlsScalar) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("序列化 BlsScalar 失败")?;
    Ok(bytes)
}

fn decode_scalar(bytes: &[u8]) -> Result<BlsScalar> {
    let mut cursor = Cursor::new(bytes);
    BlsScalar::deserialize_uncompressed(&mut cursor).context("反序列化 BlsScalar 失败")
}

fn append_scalar(out: &mut Vec<u8>, value: &BlsScalar) -> Result<()> {
    append_len_bytes(out, &encode_scalar(value)?);
    Ok(())
}

fn read_scalar(cursor: &mut Cursor<&[u8]>) -> Result<BlsScalar> {
    decode_scalar(&read_len_bytes(cursor)?)
}

fn append_scalar_vec(out: &mut Vec<u8>, values: &[BlsScalar]) -> Result<()> {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        append_scalar(out, value)?;
    }
    Ok(())
}

fn read_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<BlsScalar>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(read_scalar(cursor)?);
    }
    Ok(values)
}

fn append_bool_vec(out: &mut Vec<u8>, values: &[bool]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        out.push(u8::from(*value));
    }
}

fn read_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<bool>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let b = read_exact::<1>(cursor)?[0];
        match b {
            0 => values.push(false),
            1 => values.push(true),
            _ => bail!("bool 字段非法: {}", b),
        }
    }
    Ok(values)
}

fn append_option_scalar_vec(out: &mut Vec<u8>, values: &Option<Vec<BlsScalar>>) -> Result<()> {
    match values {
        Some(values) => {
            out.push(1);
            append_scalar_vec(out, values)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn read_option_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<BlsScalar>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_scalar_vec(cursor)?)),
        other => bail!("Option<Vec<BlsScalar>> 标记非法: {}", other),
    }
}

fn append_option_bool_vec(out: &mut Vec<u8>, values: &Option<Vec<bool>>) {
    match values {
        Some(values) => {
            out.push(1);
            append_bool_vec(out, values);
        }
        None => out.push(0),
    }
}

fn read_option_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<bool>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_bool_vec(cursor)?)),
        other => bail!("Option<Vec<bool>> 标记非法: {}", other),
    }
}

fn encode_signature(value: &Signature) -> Vec<u8> {
    value.to_der().as_bytes().to_vec()
}

fn decode_signature(bytes: &[u8]) -> Result<Signature> {
    Signature::from_der(bytes).context("反序列化 secp256k1 签名失败")
}

fn append_signature(out: &mut Vec<u8>, value: &Signature) {
    append_len_bytes(out, &encode_signature(value));
}

fn read_signature(cursor: &mut Cursor<&[u8]>) -> Result<Signature> {
    decode_signature(&read_len_bytes(cursor)?)
}

fn append_option_signature(out: &mut Vec<u8>, value: &Option<Signature>) {
    match value {
        Some(sig) => {
            out.push(1);
            append_signature(out, sig);
        }
        None => out.push(0),
    }
}

fn read_option_signature(cursor: &mut Cursor<&[u8]>) -> Result<Option<Signature>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_signature(cursor)?)),
        other => bail!("Option<Signature> 标记非法: {}", other),
    }
}

fn append_verifying_key(out: &mut Vec<u8>, value: &VerifyingKey<Secp256k1>) {
    append_len_bytes(out, value.to_encoded_point(true).as_bytes());
}

fn read_verifying_key(cursor: &mut Cursor<&[u8]>) -> Result<VerifyingKey<Secp256k1>> {
    VerifyingKey::<Secp256k1>::from_sec1_bytes(&read_len_bytes(cursor)?)
        .context("反序列化 secp256k1 公钥失败")
}

fn encode_proof(value: &Proof<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("序列化 Groth16 proof 失败")?;
    Ok(bytes)
}

fn decode_proof(bytes: &[u8]) -> Result<Proof<Bls12_381>> {
    let mut cursor = Cursor::new(bytes);
    Proof::<Bls12_381>::deserialize_uncompressed(&mut cursor)
        .context("反序列化 Groth16 proof 失败")
}

fn append_proof(out: &mut Vec<u8>, value: &Proof<Bls12_381>) -> Result<()> {
    append_len_bytes(out, &encode_proof(value)?);
    Ok(())
}

fn read_proof(cursor: &mut Cursor<&[u8]>) -> Result<Proof<Bls12_381>> {
    decode_proof(&read_len_bytes(cursor)?)
}

fn encode_ark_vk(value: &ArkVerifyingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("序列化 Groth16 verifying key 失败")?;
    Ok(bytes)
}

fn decode_ark_vk(bytes: &[u8]) -> Result<ArkVerifyingKey<Bls12_381>> {
    let mut cursor = Cursor::new(bytes);
    ArkVerifyingKey::<Bls12_381>::deserialize_uncompressed(&mut cursor)
        .context("反序列化 Groth16 verifying key 失败")
}

fn append_ark_vk(out: &mut Vec<u8>, value: &ArkVerifyingKey<Bls12_381>) -> Result<()> {
    append_len_bytes(out, &encode_ark_vk(value)?);
    Ok(())
}

fn read_ark_vk(cursor: &mut Cursor<&[u8]>) -> Result<ArkVerifyingKey<Bls12_381>> {
    decode_ark_vk(&read_len_bytes(cursor)?)
}

pub fn save_key_infor(path: impl AsRef<Path>, key: &KeyInfor) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_len_bytes(&mut out, &key.signing_key.to_bytes()[..]);
    fs::write(path, out).context("保存 KeyInfor 失败")
}

pub fn load_key_infor(path: impl AsRef<Path>) -> Result<KeyInfor> {
    let bytes = fs::read(path).context("读取 KeyInfor 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let sk_bytes = read_len_bytes(&mut cursor)?;
    if sk_bytes.len() != 32 {
        bail!("secp256k1 私钥长度应为 32 字节，实际为 {} 字节", sk_bytes.len());
    }
    let signing_key = SigningKey::<Secp256k1>::from_bytes(k256::FieldBytes::from_slice(&sk_bytes))
        .context("反序列化 secp256k1 私钥失败")?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(KeyInfor {
        signing_key,
        verifying_key,
    })
}

pub fn save_device_client_infor(path: impl AsRef<Path>, value: &DeviceClientInfor) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_verifying_key(&mut out, &value.verifying_key);
    append_string(&mut out, &value.measured_value);
    append_scalar(&mut out, &value.merkle_leaf)?;
    append_len_bytes(&mut out, &value.evidence);
    fs::write(path, out).context("保存 DeviceClientInfor 失败")
}

pub fn load_device_client_infor(path: impl AsRef<Path>) -> Result<DeviceClientInfor> {
    let bytes = fs::read(path).context("读取 DeviceClientInfor 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(DeviceClientInfor {
        verifying_key: read_verifying_key(&mut cursor)?,
        measured_value: read_string(&mut cursor)?,
        merkle_leaf: read_scalar(&mut cursor)?,
        evidence: read_len_bytes(&mut cursor)?,
    })
}

pub fn save_response_device_infor(path: impl AsRef<Path>, value: &ResponseDeviceInfor) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_verifying_key(&mut out, &value.verifying_key);
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    append_option_signature(&mut out, &value.sig);
    append_option_scalar_vec(&mut out, &value.shrubs_path)?;
    append_option_bool_vec(&mut out, &value.shrubs_tag);
    fs::write(path, out).context("保存 ResponseDeviceInfor 失败")
}

pub fn load_response_device_infor(path: impl AsRef<Path>) -> Result<ResponseDeviceInfor> {
    let bytes = fs::read(path).context("读取 ResponseDeviceInfor 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(ResponseDeviceInfor {
        verifying_key: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        sig: read_option_signature(&mut cursor)?,
        shrubs_path: read_option_scalar_vec(&mut cursor)?,
        shrubs_tag: read_option_bool_vec(&mut cursor)?,
    })
}

pub fn save_public_context(path: impl AsRef<Path>, value: &PublicContext) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_scalar_vec(&mut out, &value.root)?;
    append_verifying_key(&mut out, &value.verifier_pk);
    fs::write(path, out).context("保存 PublicContext 失败")
}

pub fn load_public_context(path: impl AsRef<Path>) -> Result<PublicContext> {
    let bytes = fs::read(path).context("读取 PublicContext 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(PublicContext {
        root: read_scalar_vec(&mut cursor)?,
        verifier_pk: read_verifying_key(&mut cursor)?,
    })
}

pub fn save_evidence_bundle(
    path: impl AsRef<Path>,
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_proof(&mut out, &evidence_reply.proof)?;
    append_ark_vk(&mut out, &evidence_reply.vk)?;
    append_signature(&mut out, &evidence_reply.sig);
    append_verifying_key(&mut out, &evidence_reply.pk);
    append_duration(&mut out, evidence_reply.timestamp);
    append_duration(&mut out, evidence_reply.period);
    append_scalar(&mut out, &evidence_reply.authorized_infor)?;
    append_signature(&mut out, device_signature);
    fs::write(path, out).context("保存 EvidenceReply 与设备签名失败")
}

pub fn load_evidence_bundle(path: impl AsRef<Path>) -> Result<(EvidenceReply, Signature)> {
    let bytes = fs::read(path).context("读取 EvidenceReply 与设备签名失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let evidence_reply = EvidenceReply {
        proof: read_proof(&mut cursor)?,
        vk: read_ark_vk(&mut cursor)?,
        sig: read_signature(&mut cursor)?,
        pk: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        authorized_infor: read_scalar(&mut cursor)?,
    };
    let device_signature = read_signature(&mut cursor)?;
    Ok((evidence_reply, device_signature))
}
