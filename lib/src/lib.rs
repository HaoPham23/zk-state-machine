use alloy_sol_types::sol;
use kzg_rs::KzgError;
use serde::{Deserialize, Serialize};
use sp1_bls12_381::{Scalar, G1Affine, G2Affine};
use std::collections::HashMap;

fn compute_lagrange_basis(tau: Scalar, domain: Vec<Scalar>) -> Result<Vec<G1Affine>, KzgError> {
    let mut basis: Vec<G1Affine> = Vec::new();
    let g1 = G1Affine::generator();
    for i in 0..domain.len() {
        let mut li = Scalar::one();
        for j in 0..domain.len() {
            if i != j {
                li *= (tau - domain[j]) * (domain[i] - domain[j]).invert().unwrap();
            }
        }
        basis.push(G1Affine::from(g1 * li));
    }
    Ok(basis)
}

// TODO: define struct G1Affine for phi

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct PublicParams {
    pub degree: usize,
    pub p: Scalar,
    pub r: Scalar,
    pub g: Scalar, // El Gamal generator
    pub g1_points: Vec<G1Affine>,
    pub g2_points: Vec<G2Affine>,
    pub g1_lagrange_basis: Vec<G1Affine>,
    pub idx: usize,
    pub v: Vec<Scalar>,
    pub t: Vec<Scalar>,
    pub pkeys: Vec<Scalar>,
    pub index_of: HashMap<[u8; 32], usize>,
}

impl PublicParams {
    pub fn new(degree: usize, p: Scalar, r: Scalar, g: Scalar, g1_points: Vec<G1Affine>, g2_points: Vec<G2Affine>, g1_lagrange_basis: Vec<G1Affine>) -> PublicParams {
        PublicParams {
            degree,
            p,
            r,
            g,
            g1_points,
            g2_points,
            g1_lagrange_basis,
            idx: 0,
            v: vec![Scalar::zero(); degree],
            t: vec![Scalar::zero(); degree],
            pkeys: Vec::new(),
            index_of: HashMap::new(),
        }
    }

    pub fn setup(degree: usize) -> PublicParams {
        let p = Scalar::from_raw([0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a]);
        let r = Scalar::from_raw([0xFFFFFFFF00000001, 0x53BDA402FFFE5BFE, 0x3339D80809A1D805, 0x73EDA753299D7D48]);
        let tau = Scalar::from(9999); // TODO: need random
        let g = Scalar::from(2);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let mut g1_points = Vec::new();
        let mut g2_points = Vec::new();
        let mut tau_pow = Scalar::from(1);
        for _ in 0..degree {
            tau_pow *= tau;
            g1_points.push(G1Affine::from(g1 * tau_pow));
            g2_points.push(G2Affine::from(g2 * tau_pow));
        }
        let domain = (0..degree).map(|i| Scalar::from(i as u64)).collect();
        let g1_lagrange_basis = compute_lagrange_basis(tau, domain).unwrap();
        PublicParams {
            degree,
            p,
            r,
            g,
            g1_points,
            g2_points,
            g1_lagrange_basis,
            idx: 0,
            v: vec![Scalar::zero(); degree],
            t: vec![Scalar::zero(); degree],
            pkeys: Vec::new(),
            index_of: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct KZG {
    g1_lagrange_basis: Vec<G1Affine>
}

impl KZG {
    pub fn new(g1_lagrange_basis: Vec<G1Affine>) -> KZG {
        KZG {
            g1_lagrange_basis
        }
    }

    pub fn commit(&self, poly: Vec<Scalar>) -> Result<G1Affine, KzgError> {
        let mut commitment = G1Affine::identity();
        for (i, ai) in poly.iter().enumerate() {
            let coeff = G1Affine::from(self.g1_lagrange_basis[i] * ai);
            commitment = commitment.add_affine(&coeff);
        }
        Ok(commitment)
    }
}

pub struct ElGamal {
    g: Scalar
}

impl ElGamal {
    pub fn new(g: Scalar) -> ElGamal {
        ElGamal {
            g
        }
    }

    pub fn from_skey(&self, sk: [u64; 4]) -> Scalar {
        self.g.pow(&sk)
    }

    pub fn encrypt(&self, pk: Scalar, m: u64, r: [u64; 4]) -> (Scalar, Scalar) {
        let c1 = self.g.pow(&r);
        let exp = [m, 0, 0, 0];
        let c2 = self.g.pow(&exp) * pk.pow(&r);
        (c1, c2)
    }

    pub fn decrypt(&self, sk: [u64; 4], c1: Scalar, c2: Scalar, x: u64) -> Result<u64, String> {
        let c1_pow_sk_inv = c1.pow(&sk).invert().unwrap();
        let c2_div_c1 = c2 * c1_pow_sk_inv;
        if self.g.pow(&[x, 0, 0, 0]) == c2_div_c1 {
            return Ok(x);
        }
        Err("Decryption failed".to_string())
    }
}

pub fn deposit(pp: &mut PublicParams, pk_a: Scalar, r_a: [u64; 4], m_a: u64 , phi: G1Affine) -> Result<G1Affine, String> {
    if pp.idx >= pp.degree {
        return Err("Deposit failed".to_string());
    }
    let el_gamal = ElGamal::new(pp.g);
    let (t, v) = el_gamal.encrypt(pk_a, m_a, r_a);
    pp.t[pp.idx] = t;
    pp.v[pp.idx] = v;
    pp.pkeys.push(pk_a);
    pp.index_of.insert(pk_a.to_bytes(), pp.idx);
    let e = G1Affine::from(v * pp.g1_lagrange_basis[pp.idx]);
    let next_phi = phi.add_affine(&e);
    pp.idx += 1;
    Ok(next_phi)
}

pub fn withdraw(pp: &mut PublicParams, sk: [u64; 4], r: [u64; 4], balance: u64,  amount: u64, phi: G1Affine, recipient: [u8; 20]) -> Result<G1Affine, String> {
    let el_gamal = ElGamal::new(pp.g);
    let g_r = pp.g.pow(&r);
    let pk = el_gamal.from_skey(sk);
    let idx = match pp.index_of.get(&pk.to_bytes()) {
        Some(idx) => *idx,
        None => return Err("Public key not found".to_string())
    };
    if idx >= pp.degree || pp.t[idx] != g_r {
        return Err("Withdraw failed".to_string());
    }
    let c1 = pp.t[idx];
    let c2 = pp.v[idx];
    let m = el_gamal.decrypt(sk, c1, c2, balance).unwrap();
    if amount > m {
        return Err("Withdraw exceeds balance".to_string());
    }
    let delta = c2 * (pp.g.pow(&[amount, 0, 0, 0]).invert().unwrap() - Scalar::one());
    let multiplier = G1Affine::from(pp.g1_lagrange_basis[idx] * delta);
    let next_phi = phi.add_affine(&multiplier);
    pp.v[idx] *= pp.g.pow(&[amount, 0, 0, 0]).invert().unwrap();
    let _ = recipient;
    Ok(next_phi)
}

pub fn send(pp: &mut PublicParams, sk_sender: [u64; 4], pk_receiver: Scalar, balance: u64, amount: u64, phi: G1Affine) -> Result<G1Affine, String> {
    let el_gamal = ElGamal::new(pp.g);
    let pk_sender = el_gamal.from_skey(sk_sender);
    let idx_sender = match pp.index_of.get(&pk_sender.to_bytes()) {
        Some(idx) => *idx,
        None => return Err("Public key not found!".to_string())
    };
    let idx_receiver = match pp.index_of.get(&pk_receiver.to_bytes()) {
        Some(idx) => *idx,
        None => return Err("Public key not found".to_string())
    };
    println!("idx_sender: {:?}", idx_sender);
    println!("idx_receiver: {:?}", idx_receiver);
    if idx_sender >= pp.degree || idx_receiver >= pp.degree {
        return Err("Send failed".to_string());
    }
    let m = el_gamal.decrypt(sk_sender, pp.t[idx_sender], pp.v[idx_sender], balance).unwrap();
    if amount > m {
        return Err("Send exceeds balance".to_string());
    }
    let delta_sender = pp.v[idx_sender] * (pp.g.pow(&[amount, 0, 0, 0]).invert().unwrap() - Scalar::one());
    let delta_receiver = pp.v[idx_receiver] * (pp.g.pow(&[amount, 0, 0, 0]) - Scalar::one());
    let multiplier_sender = G1Affine::from(pp.g1_lagrange_basis[idx_sender] * delta_sender);
    let multiplier_receiver = G1Affine::from(pp.g1_lagrange_basis[idx_receiver] * delta_receiver);
    let next_phi = phi.add_affine(&multiplier_sender).add_affine(&multiplier_receiver);
    pp.v[idx_sender] *= pp.g.pow(&[amount, 0, 0, 0]).invert().unwrap();
    pp.v[idx_receiver] *= pp.g.pow(&[amount, 0, 0, 0]);
    Ok(next_phi)
}

pub fn rotate(pp: &mut PublicParams, skey: [u64; 4] , new_additive: [u64; 4], phi: G1Affine) -> Result<(G1Affine, usize), String> {
    let el_gamal = ElGamal::new(pp.g);
    let pkey = el_gamal.from_skey(skey);
    let idx = match pp.index_of.get(&pkey.to_bytes()) {
        Some(idx) => *idx,
        None => return Err("Public key not found".to_string())
    };
    let delta = pp.v[idx] * (pkey.pow(&new_additive) - Scalar::one());
    let multiplier = G1Affine::from(pp.g1_lagrange_basis[idx] * delta);
    let next_phi = phi.add_affine(&multiplier);
    pp.t[idx] *= pp.g.pow(&new_additive);
    pp.v[idx] *= pkey.pow(&new_additive);
    Ok((next_phi, idx))
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesDeposit {
        bytes old_phi;
        bytes next_phi;
        uint256 amount;
        bytes32 pkey;
        bytes32 t;
    }

    struct PublicValuesSend {
        bytes old_phi;
        bytes next_phi;
    }

    struct PublicValuesWithdraw {
        bytes old_phi;
        bytes next_phi;
        uint256 amount;
        address recipient;
    }

    struct PublicValuesRotate {
        bytes old_phi;
        bytes next_phi;
        bytes32 pkey;
        bytes32 new_t;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Deposit {
    pub amount: u64,
    pub pkey: Scalar,
    pub random: [u64; 4],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Send {
    pub balance_sender: u64,
    pub amount: u64,
    pub skey_sender: [u64; 4],
    pub pkey_receiver: Scalar,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Withdraw {
    pub balance: u64,
    pub amount: u64,
    pub skey: [u64; 4],
    pub random: [u64; 4],
    pub recipient: [u8; 20],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rotate {
    pub skey: [u64; 4],
    pub new_additive: [u64; 4],
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    Deposit(Deposit),
    Send(Send),
    Withdraw(Withdraw),
    Rotate(Rotate),
}