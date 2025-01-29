#[allow(unused)]

use kzg_rs::{FIAT_SHAMIR_PROTOCOL_DOMAIN};
use kzg_rs::{trusted_setup::KzgSettings, KzgError};
use ff::{Field, PrimeField};
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

fn compute_lagrange_basis(kzg_settings: &KzgSettings) -> Result<Vec<G1Affine>, KzgError> {
    let g1 = kzg_settings.g1_points;
    let domain = kzg_settings.roots_of_unity;
    let mut basis: Vec<G1Affine> = Vec::new();
    for i in 0..domain.len() {
        let mut coeff = G1Affine::identity();
        for j in 0..domain.len() {
            println!("{:?} {:?}", i, j);
            if i != j {
                let numerator = G1Affine::from(g1[0] * domain[j].neg()); // -j*G1
                let denominator = domain[i] - domain[j];
                let denominator = denominator.invert().unwrap();
                coeff = G1Affine::from(g1[1].add_affine(&numerator) * denominator);
            }
        }
        basis.push(coeff);
    }
    Ok(basis)
    
}

// #[derive(PrimeField)]
// #[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
// #[PrimeFieldGenerator = "2"]
// #[PrimeFieldReprEndianness = "little"]
// struct Fr([u64; 4]);

struct PublicParams {
    pub p: Scalar,
    pub r: Scalar,
    pub tau: Scalar,
    pub g: Scalar, // El Gamal generator
    pub g1s: Vec<G1Affine>,
    pub g2s: Vec<G2Affine>
}

const D: usize = 16;
const P: Scalar = Scalar([0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a]);
const R: Scalar = Scalar([0xFFFFFFFF00000001, 0x53BDA402FFFE5BFE, 0x3339D80809A1D805, 0x73EDA753299D7D48]);

impl PublicParams {
    fn setup() {
        let p = P;
        let r = R;
        let g = Field::ONE;
        let tau = Scalar::from(2); // TODO: random
        let g1 = G1Affine::identity();
        let g2 = G2Affine::identity();
        let mut G1s = Vec::new();
        let mut G2s = Vec::new();
        for i in 0..D {
            tau_power = tau.pow(Scalar::from(i as u64).unwrap());
            G1s.push(G1Affine::from(g1 * Scalar::from(i as u64).pow(i)));
            G2s.push(G2Affine::from(g2 * Scalar::from(i as u64)));
        }
        PublicParams {
            p,
            r,
            g,
            G1s,
            G2s
        }
    }
}

fn setup() -> Result<KzgSettings, KzgError> {
    const DEG: usize = 16;
    let tau = Scalar::from(2); // random tau
    let mut domain: [Scalar; DEG] = [Scalar::from(0); DEG];
    for i in 0..DEG {
        domain[i] = Scalar::from(i as u64);
    }
    let g1 = G1Affine::identity();
    let mut g1_points = [g1; DEG as usize];
    for i in 0..DEG {
        g1_points[i] = G1Affine::from(g1 * domain[i]);
    }
}

fn main() {
    let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
    println!("{:?}", FIAT_SHAMIR_PROTOCOL_DOMAIN);

    let base = sp1_bls12_381::Scalar::from(2);
    let v = kzg_rs::kzg_proof::compute_powers(&base, 1);
    println!("{:?}", v);
    let basis = compute_lagrange_basis(&kzg_settings).unwrap();
    println!("{:?}", commit_evaluation(v, basis, &kzg_settings).unwrap());
}