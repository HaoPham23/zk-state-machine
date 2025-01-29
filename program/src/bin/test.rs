#[allow(unused)]
use kzg_rs::{trusted_setup::KzgSettings, KzgError};
use sp1_bls12_381::{Scalar, G1Affine, G2Affine};
use alloy_sol_types::SolType;

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

#[derive(Debug,Clone)]
struct PublicParams {
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
    fn new(degree: usize, p: Scalar, r: Scalar, g: Scalar, g1_points: Vec<G1Affine>, g2_points: Vec<G2Affine>, g1_lagrange_basis: Vec<G1Affine>) -> PublicParams {
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

    fn setup(degree: usize) -> PublicParams {
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
struct KZG {
    g1_points: Vec<G1Affine>,
    g2_points: Vec<G2Affine>,
    g1_lagrange_basis: Vec<G1Affine>
}

impl KZG {
    fn new(g1_points: Vec<G1Affine>, g2_points: Vec<G2Affine>, g1_lagrange_basis: Vec<G1Affine>) -> KZG {
        KZG {
            g1_points,
            g2_points,
            g1_lagrange_basis
        }
    }

    fn commit(&self, poly: Vec<Scalar>) -> Result<G1Affine, KzgError> {
        let mut commitment = G1Affine::identity();
        for i in 0..poly.len() {
            let coeff = G1Affine::from(self.g1_lagrange_basis[i] * poly[i]);
            commitment = commitment.add_affine(&coeff);
        }
        Ok(commitment)
    }
}

struct ElGamal {
    p: Scalar,
    g: Scalar
}

impl ElGamal {
    fn new(p: Scalar, g: Scalar) -> ElGamal {
        ElGamal {
            p,
            g
        }
    }

    fn key_gen(&self) -> ([u64; 4], Scalar) {
        let sk = [0x3039u64, 0, 0, 0]; // TODO: need random
        println!("sk: {:?}", sk);
        let pk = self.g.pow(&sk);
        (sk, pk)
    }

    fn encrypt(&self, pk: Scalar, m: u64, r: [u64; 4]) -> (Scalar, Scalar) {
        let c1 = self.g.pow(&r);
        let exp = [m, 0, 0, 0];
        let c2 = self.g.pow(&exp) * pk.pow(&r);
        (c1, c2)
    }

    fn decrypt(&self, sk: [u64; 4], c1: Scalar, c2: Scalar) -> Result<u64, String> {
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

fn key_gen(pp: &PublicParams) -> ([u64; 4], Scalar) {
    let el_gamal = ElGamal::new(pp.r, pp.g);
    let (sk, pk) = el_gamal.key_gen();
    (sk, pk)
}


fn deposit(pp: &mut PublicParams, pk_a: Scalar, r_a: [u64; 4], m_a: u64 , phi: G1Affine) -> Result<G1Affine, String> {
    if pp.idx >= pp.degree {
        return Err("Deposit failed".to_string());
    }
    let el_gamal = ElGamal::new(pp.r, pp.g);
    let (t, v) = el_gamal.encrypt(pk_a, m_a, r_a);
    pp.t[pp.idx] = t;
    pp.v[pp.idx] = v;
    let e = G1Affine::from(v * pp.g1_lagrange_basis[pp.idx]);
    let next_phi = phi.add_affine(&e);
    pp.idx += 1;
    Ok(next_phi)
}

fn withdraw(pp: &mut PublicParams, sk: [u64; 4], r: [u64; 4], amount: u64, phi: G1Affine, A: [u8; 20]) -> Result<G1Affine, String> {
    let el_gamal = ElGamal::new(pp.r, pp.g);
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

fn main() {
    let mut pp = PublicParams::setup(16);
    let kzg = KZG::new(pp.g1_points.clone(), pp.g2_points.clone(), pp.g1_lagrange_basis.clone());
    let v = vec![Scalar::zero(); pp.degree];
    let mut phi = kzg.commit(v).unwrap();
    println!("{:?}", phi);
    let (skA, pkA) = key_gen(&pp);
    let (skB, pkB) = key_gen(&pp);
    println!("User A's public key: {:?}", pkA);
    println!("User B's public key: {:?}", pkB);
    println!("User B's secret key: {:?}", skB);

    let (mA, mB) = (100u64, 200u64);    
    let (rA, rB) = ([0x1111u64, 0, 0, 0], [0x2222u64, 0, 0, 0]); // TODO: need random
    println!("User A generates random number r = {:?}", rA);
    println!("User A deposits: {:?} ETH", mA);
    println!("Update state...");

    phi = deposit(&mut pp, pkA, rA, mA, phi).unwrap();
    println!("{:?}", phi);

}