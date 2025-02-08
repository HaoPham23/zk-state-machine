use alloy_sol_types::sol;
use kzg_rs::{trusted_setup::KzgSettings, KzgError};
use serde::{Deserialize, Serialize};
use sp1_bls12_381::{Scalar, G1Affine, G2Affine};

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
        }
    }
}

#[derive(Debug)]
pub struct KZG {
    g1_points: Vec<G1Affine>,
    g2_points: Vec<G2Affine>,
    g1_lagrange_basis: Vec<G1Affine>
}

impl KZG {
    pub fn new(g1_points: Vec<G1Affine>, g2_points: Vec<G2Affine>, g1_lagrange_basis: Vec<G1Affine>) -> KZG {
        KZG {
            g1_points,
            g2_points,
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

    pub fn key_gen(&self) -> ([u64; 4], Scalar) {
        let sk = [0x3039u64, 0, 0, 0]; // TODO: need random
        println!("sk: {:?}", sk);
        let pk = self.g.pow(&sk);
        (sk, pk)
    }

    pub fn encrypt(&self, pk: Scalar, m: u64, r: [u64; 4]) -> (Scalar, Scalar) {
        let c1 = self.g.pow(&r);
        let exp = [m, 0, 0, 0];
        let c2 = self.g.pow(&exp) * pk.pow(&r);
        (c1, c2)
    }

    pub fn decrypt(&self, sk: [u64; 4], c1: Scalar, c2: Scalar) -> Result<u64, String> {
        let c1_pow_sk_inv = c1.pow(&sk).invert().unwrap();
        let c2_div_c1 = c2 * c1_pow_sk_inv;
        for m in 0..1000 {
            let exp = [m, 0, 0, 0];
            if self.g.pow(&exp) == c2_div_c1 {
                return Ok(m);
            }
        }
        Err("Decryption failed".to_string())
    }
}

pub fn key_gen(pp: &PublicParams) -> ([u64; 4], Scalar) {
    let el_gamal = ElGamal::new(pp.g);
    let (sk, pk) = el_gamal.key_gen();
    (sk, pk)
}

pub fn deposit(pp: &mut PublicParams, pk_a: Scalar, r_a: [u64; 4], m_a: u64 , phi: G1Affine) -> Result<G1Affine, String> {
    if pp.idx >= pp.degree {
        return Err("Deposit failed".to_string());
    }
    let el_gamal = ElGamal::new(pp.g);
    let (t, v) = el_gamal.encrypt(pk_a, m_a, r_a);
    pp.t[pp.idx] = t;
    pp.v[pp.idx] = v;
    let e = G1Affine::from(v * pp.g1_lagrange_basis[pp.idx]);
    let next_phi = phi.add_affine(&e);
    pp.idx += 1;
    Ok(next_phi)
}

pub fn withdraw(pp: &mut PublicParams, sk: [u64; 4], r: [u64; 4], amount: u64, phi: G1Affine, A: [u8; 20]) -> Result<G1Affine, String> {
    let el_gamal = ElGamal::new(pp.g);
    let g_r = pp.g.pow(&r);
    for idx in 0..pp.degree {
        if pp.t[idx] == g_r {
            let c1 = pp.t[idx];
            let c2 = pp.v[idx];
            let m = el_gamal.decrypt(sk, c1, c2).unwrap();
            if amount > m {
                return Err("Withdraw exceeds balance".to_string());
            }
            let delta = c2 * (pp.g.pow(&[amount, 0, 0, 0]).invert().unwrap() - Scalar::one());
            let multiplier = G1Affine::from(pp.g1_lagrange_basis[idx] * delta);
            let next_phi = phi.add_affine(&multiplier);
            pp.v[idx] *= pp.g.pow(&[amount, 0, 0, 0]).invert().unwrap();
            return Ok(next_phi);
        }
    }
    Err("Withdraw failed".to_string())
}

pub fn send(pp: &mut PublicParams, sk_sender: [u64; 4], pk_receiver: Scalar, amount: u64, phi: G1Affine) -> Result<G1Affine, String> {
    let el_gamal = ElGamal::new(pp.g);
    let (idx_sender, idx_receiver) = (1, 0); // TODO: Need to find
    let m = el_gamal.decrypt(sk_sender, pp.t[idx_sender], pp.v[idx_sender]).unwrap();
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


sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 x;
    }
}

sol! {
    struct PublicValuesWithdraw {
        uint64 amount;
        uint256 old_state;
        uint256 new_state;
        address A;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}
