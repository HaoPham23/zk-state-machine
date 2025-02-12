#[allow(unused)]
use state_machine_lib::{PublicParams, ElGamal, KZG, deposit, send, withdraw, rotate};
use sp1_bls12_381::{Scalar, G1Affine};
use hex::decode;

fn print_state(phi: G1Affine, pp: &PublicParams, time: &mut u64) {
    *time += 1;
    println!("At time t = {}:", *time);
    println!("[+] phi_{} = {:?}", *time, phi);
    // println!("[+] v = {:?}", pp.v);
    // println!("[+] t = {:?}", pp.t);
    let kzg = KZG::new(pp.g1_points.clone(), pp.g2_points.clone(), pp.g1_lagrange_basis.clone());
    assert_eq!(kzg.commit(pp.v.clone()).unwrap(), phi);
}

fn main() {
    let mut pp = PublicParams::setup(16);
    let el_gamal = ElGamal::new(pp.g);
    let kzg = KZG::new(pp.g1_points.clone(), pp.g2_points.clone(), pp.g1_lagrange_basis.clone());
    let v = vec![Scalar::zero(); pp.degree];
    let mut phi = kzg.commit(v).unwrap();
    println!("{:?}", phi);
    let mut time = 0;
    let sk_a = [1u64, 2, 3, 4];
    let pk_a = el_gamal.from_skey(sk_a);
    let sk_b = [5u64, 6, 7, 8];
    let pk_b = el_gamal.from_skey(sk_b);

    println!("User A's public key: {:?}", pk_a);
    println!("User B's public key: {:?}", pk_b);
    println!("User B's secret key: {:?}", sk_b);

    let (mut m_a, mut m_b) = (100u64, 200u64);    
    let (r_a, r_b) = ([0x1111u64, 0, 0, 0], [0x2222u64, 0, 0, 0]); // TODO: need random
    println!("User A generates random number r = {:?}", r_a);
    println!("User A deposits: {:?} ETH", m_a);
    println!("Update state...");

    phi = deposit(&mut pp, pk_a, r_a, m_a, phi).unwrap();
    print_state(phi, &pp, &mut time);

    println!("User B deposits: {:?} ETH", m_b);
    println!("Update state...");

    phi = deposit(&mut pp, pk_b, r_b, m_b, phi).unwrap();
    print_state(phi, &pp, &mut time);

    let amount = 30u64;
    println!("User B sends {:?} ETH to User A", amount);
    println!("Update state...");

    phi = send(&mut pp, sk_b, pk_a, m_b, amount, phi).unwrap();
    print_state(phi, &pp, &mut time);
    m_b -= amount;
    m_a += amount;

    let withdraw_amount = 10u64;

    println!("User A withdraws {:?} ETH", withdraw_amount);
    println!("Update state...");

    // private key: 0xc0cf034c2039fbb095aad1cd7dfd8854eddc5fcfed04e009520049107022b22b
    let A = "65f697a02d756Cf4BC3465c1cC60dB3a4AF19521"; // TODO: need address
    let A: [u8; 20] = decode(A).unwrap().try_into().unwrap();
    phi = withdraw(&mut pp, sk_a, r_a, m_a, amount, phi, A).unwrap();
    print_state(phi, &pp, &mut time);
    m_a -= amount;

    let amount = 101u64;
    println!("User A withdraws {:?} ETH", amount);
    println!("Update state...");

    let tmp = withdraw(&mut pp, sk_a, r_a, m_a, amount, phi, A);
    match tmp {
        Ok(_) => {
            phi = tmp.unwrap();
            print_state(phi, &pp, &mut time)
        },
        Err(e) => println!("ERROR, should panic: {}", e)
    }

    let add_additive = [1u64, 0, 0, 0];
    let new_r = [0x1112u64, 0, 0, 0]; // = r_a + add_additive
    println!("User A rotates his secret");
    println!("Update state...");
    phi = rotate(&mut pp, sk_a, add_additive, phi).unwrap();
    print_state(phi, &pp, &mut time);

    println!("User A withdraws {:?} ETH using old secret", amount);
    println!("Update state...");
    let tmp = withdraw(&mut pp, sk_a, r_a, m_a, amount, phi, A);
    match tmp {
        Ok(_) => {
            phi = tmp.unwrap();
            print_state(phi, &pp, &mut time)
        },
        Err(e) => println!("ERROR, should panic: {}", e)
    }

    println!("User A withdraws {:?} ETH using new secret", 100);
    println!("Update state...");
    phi = withdraw(&mut pp, sk_a, new_r, m_a, 100, phi, A).unwrap();
    print_state(phi, &pp, &mut time);
}