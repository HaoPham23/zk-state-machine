#[allow(unused)]

use kzg_rs::{FIAT_SHAMIR_PROTOCOL_DOMAIN};
use kzg_rs::{trusted_setup::KzgSettings, KzgError};
use sp1_bls12_381::{Scalar, G1Affine, G2Affine};

fn commit(poly: Vec<Scalar>, kzg_settings: &KzgSettings) -> Result<G1Affine, KzgError> {
    let g1 = kzg_settings.g1_points;
    let mut commitment = sp1_bls12_381::G1Affine::identity();
    for i in 0..poly.len() {
        let coeff = G1Affine::from(g1[i] * poly[i]);
        commitment = commitment.add_affine(&coeff);
    }
    Ok(commitment)
}

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

const D: usize = 16;
const P: Scalar = Scalar([0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a]);
const R: Scalar = Scalar([0xFFFFFFFF00000001, 0x53BDA402FFFE5BFE, 0x3339D80809A1D805, 0x73EDA753299D7D48]);
const TAU: Scalar = Scalar([0x5, 0x0, 0x0, 0x0]);

#[derive(Debug)]
struct PublicParams {
    pub p: Scalar,
    pub r: Scalar,
    pub g: Scalar, // El Gamal generator
    pub g1_points: Vec<G1Affine>,
    pub g2_points: Vec<G2Affine>,
    pub g1_lagrange_basis: Vec<G1Affine>,
}

impl PublicParams {
    fn new(p: Scalar, r: Scalar, g: Scalar, g1_points: Vec<G1Affine>, g2_points: Vec<G2Affine>, g1_lagrange_basis: Vec<G1Affine>) -> PublicParams {
        PublicParams {
            p,
            r,
            g,
            g1_points,
            g2_points,
            g1_lagrange_basis
        }
    }

    fn setup() -> PublicParams {
        let p = P;
        let r = R;
        let g = Scalar::from(2);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let mut g1_points = Vec::new();
        let mut g2_points = Vec::new();
        let mut tau_pow = Scalar::from(1);
        for _ in 0..D {
            tau_pow *= TAU;
            g1_points.push(G1Affine::from(g1 * tau_pow));
            g2_points.push(G2Affine::from(g2 * tau_pow));
        }
        let domain = (0..D).map(|i| Scalar::from(i as u64)).collect();
        let g1_lagrange_basis = compute_lagrange_basis(TAU, domain).unwrap();
        PublicParams {
            p,
            r,
            g,
            g1_points,
            g2_points,
            g1_lagrange_basis,
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

fn main() {
    let pp = PublicParams::setup();
    let kzg = KZG::new(pp.g1_points, pp.g2_points, pp.g1_lagrange_basis);
    let v = vec![Scalar::one(); D];
    println!("{:?}", kzg.commit(v).unwrap());
}