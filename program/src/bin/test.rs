#[allow(unused)]
use state_machine_lib::{PublicParams, KZG, key_gen, deposit, send, withdraw};
use sp1_bls12_381::{Scalar, G1Affine};

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
    let kzg = KZG::new(pp.g1_points.clone(), pp.g2_points.clone(), pp.g1_lagrange_basis.clone());
    let v = vec![Scalar::zero(); pp.degree];
    let mut phi = kzg.commit(v).unwrap();
    println!("{:?}", phi);
    let mut time = 0;
    let (sk_a, pk_a) = key_gen(&pp);
    let (sk_b, pk_b) = key_gen(&pp);
    println!("User A's public key: {:?}", pk_a);
    println!("User B's public key: {:?}", pk_b);
    println!("User B's secret key: {:?}", sk_b);

    let (m_a, m_b) = (100u64, 200u64);    
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

    phi = send(&mut pp, sk_b, pk_a, amount, phi).unwrap();
    print_state(phi, &pp, &mut time);

    println!("User A withdraws {:?} ETH", amount);
    println!("Update state...");

    let A = [0u8; 20]; // TODO: need address
    phi = withdraw(&mut pp, sk_a, r_a, amount, phi, A).unwrap();
    print_state(phi, &pp, &mut time);

    let amount = 101u64;
    println!("User A withdraws {:?} ETH", amount);
    println!("Update state...");

    let tmp = withdraw(&mut pp, sk_a, r_a, amount, phi, A);
    match tmp {
        Ok(_) => {
            phi = tmp.unwrap();
            print_state(phi, &pp, &mut time)
        },
        Err(e) => println!("ERROR, should panic: {}", e)
    }
}