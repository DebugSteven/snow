#![feature(test)]

extern crate test;
extern crate screech;
extern crate rustc_serialize;

use screech::*;
use std::ops::DerefMut;
use self::rustc_serialize::hex::ToHex;
use test::Bencher;

const MSG_SIZE: usize = 4096;

struct RandomInc {
    next_byte: u8
}

impl Default for RandomInc {

    fn default() -> RandomInc {
        RandomInc {next_byte: 0}
    }
}

impl RandomType for RandomInc {

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for count in 0..out.len() {
            out[count] = self.next_byte;
            if self.next_byte == 255 {
                self.next_byte = 0;
            } else {
                self.next_byte += 1;
            }
        }
    }
}

struct TestResolver {
    next_byte: u8,
    parent: DefaultResolver,
}

impl TestResolver {
    pub fn new(next_byte: u8) -> Self {
        TestResolver{ next_byte: next_byte, parent: DefaultResolver }
    }

    pub fn next_byte(&mut self, next_byte: u8) {
        self.next_byte = next_byte;
    }
}

impl CryptoResolver for TestResolver {
    fn resolve_rng(&self) -> Option<Box<RandomType>> {
        let mut rng = RandomInc::default();
        rng.next_byte = self.next_byte;
        Some(Box::new(rng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<DhType>> {
        self.parent.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<HashType>> {
        self.parent.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<CipherStateType>> {
        self.parent.resolve_cipher(choice)
    }
}

pub fn copy_memory(data: &[u8], out: &mut [u8]) -> usize {
    for count in 0..data.len() {out[count] = data[count];}
    data.len()
}

#[bench]
fn bench_write_message_punk(b: &mut Bencher) {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());

    let resolver_i = TestResolver::new(32);
    let resolver_r = TestResolver::new(33);

    let mut h_i = NoiseBuilder::with_resolver("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap(),
                                              Box::new(resolver_i))
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::with_resolver("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap(),
                                              Box::new(resolver_r))
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap().0 == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
    assert!(buffer_out[..3].to_hex() == "616263");

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap().0 == 100);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap().0 == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap().0 == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

    b.bytes = MSG_SIZE as u64;
    b.iter(move || h_i.write_message(&['A' as u8; MSG_SIZE], &mut buffer_msg).unwrap());
}

#[bench]
fn bench_write_message_nist(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);

    let pattern = "Noise_XX_25519_AESGCM_SHA256";
    let mut h_i = NoiseBuilder::new("Noise_XX_25519_AESGCM_SHA256".parse().unwrap())
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new("Noise_XX_25519_AESGCM_SHA256".parse().unwrap())
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap().0 == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
    assert!(buffer_out[..3].to_hex() == "616263");

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap().0 == 100);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap().0 == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap().0 == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

    b.bytes = MSG_SIZE as u64;
    b.iter(move || h_i.write_message(&['A' as u8; MSG_SIZE], &mut buffer_msg).unwrap());
}

#[bench]
fn bench_read_and_write_message_punk(b: &mut Bencher) {
    let mut static_i: Dh25519 = Default::default();
    let mut static_r: Dh25519 = Default::default();

    let mut rand = RandomOs::default();
    static_i.generate(&mut rand);
    static_r.generate(&mut rand);

    let mut pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    let mut h_i = NoiseBuilder::new(pattern.parse().unwrap())
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::new(pattern.parse().unwrap())
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];

    // get the handshaking out of the way for even testing
    h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap();
    h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap();
    h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap();

    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        let len = h_i.write_message(&[0u8;MSG_SIZE], &mut buffer_msg).unwrap().0;
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    });
}

#[bench]
fn bench_read_and_write_message_nist(b: &mut Bencher) {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());

    let resolver_i = TestResolver::new(32);
    let resolver_r = TestResolver::new(33);

    let mut h_i = NoiseBuilder::with_resolver("Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
                                              Box::new(resolver_i))
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::with_resolver("Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
                                              Box::new(resolver_r))
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap().0 == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
    assert!(buffer_out[..3].to_hex() == "616263");

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap().0 == 100);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap().0 == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap().0 == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

    b.bytes = MSG_SIZE as u64;
    b.iter(move || {
        let len = h_i.write_message(&[0u8;MSG_SIZE], &mut buffer_msg).unwrap().0;
        h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    });
}

// XXX this test is really shit and might crash on different machines
#[bench]
fn bench_read_message_nist(b: &mut Bencher) {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());

    let resolver_i = TestResolver::new(32);
    let resolver_r = TestResolver::new(33);

    let mut h_i = NoiseBuilder::with_resolver("Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
                                              Box::new(resolver_i))
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::with_resolver("Noise_XX_25519_AESGCM_SHA256".parse().unwrap(),
                                              Box::new(resolver_r))
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap().0 == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
    assert!(buffer_out[..3].to_hex() == "616263");

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap().0 == 100);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap().0 == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap().0 == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

    let mut messages = vec![vec![0u8; MSG_SIZE * 2]; 1024];
    let mut len = 0;
    for i in 0..1024 {
        len = h_i.write_message(&[0u8;MSG_SIZE], &mut messages[i]).unwrap().0;
    }
    b.bytes = MSG_SIZE as u64;
    let mut i = 0;
    b.iter(move || {
        h_r.read_message(&messages[i][..len], &mut buffer_out).unwrap();
        i += 1;
    });
}

// XXX this test is really shit and might crash on different machines
#[bench]
fn bench_read_message_punk(b: &mut Bencher) {
    let resolver_i = TestResolver::new(0);
    let resolver_r = TestResolver::new(1);

    let mut static_i:Dh25519 = Default::default();
    let mut static_r:Dh25519 = Default::default();

    static_i.generate(resolver_i.resolve_rng().unwrap().deref_mut());
    static_r.generate(resolver_r.resolve_rng().unwrap().deref_mut());

    let resolver_i = TestResolver::new(32);
    let resolver_r = TestResolver::new(33);

    let mut h_i = NoiseBuilder::with_resolver("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse().unwrap(),
                                              Box::new(resolver_i))
        .local_private_key(static_i.privkey())
        .build_initiator().unwrap();
    let mut h_r = NoiseBuilder::with_resolver("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse().unwrap(),
                                              Box::new(resolver_r))
        .local_private_key(static_r.privkey())
        .build_responder().unwrap();

    let mut buffer_msg = [0u8; MSG_SIZE * 2];
    let mut buffer_out = [0u8; MSG_SIZE * 2];
    assert!(h_i.write_message("abc".as_bytes(), &mut buffer_msg).unwrap().0 == 35);
    assert!(h_r.read_message(&buffer_msg[..35], &mut buffer_out).unwrap().0 == 3);
    assert!(buffer_out[..3].to_hex() == "616263");

    assert!(h_r.write_message("defg".as_bytes(), &mut buffer_msg).unwrap().0 == 100);
    assert!(h_i.read_message(&buffer_msg[..100], &mut buffer_out).unwrap().0 == 4);
    assert!(buffer_out[..4].to_hex() == "64656667");

    assert!(h_i.write_message(&[0u8;0], &mut buffer_msg).unwrap().0 == 64);
    assert!(h_r.read_message(&buffer_msg[..64], &mut buffer_out).unwrap().0 == 0);

    let mut messages = vec![vec![0u8; MSG_SIZE * 2]; 1024];
    let mut len = 0;
    for i in 0..1024 {
        len = h_i.write_message(&[0u8;MSG_SIZE], &mut messages[i]).unwrap().0;
    }
    b.bytes = MSG_SIZE as u64;
    let mut i = 0;
    b.iter(move || {
        h_r.read_message(&messages[i][..len], &mut buffer_out).unwrap();
        i += 1;
    });
}

#[bench]
fn bench_new_builder_from_string_with_key(b: &mut Bencher) {
    let static_i:Dh25519 = Default::default();
    let privkey = static_i.privkey();
    b.iter(move || {
        NoiseBuilder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .local_private_key(privkey)
                .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_from_string_skeleton(b: &mut Bencher) {
    b.iter(move || {
        NoiseBuilder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
            .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_from_params_skeleton(b: &mut Bencher) {
    b.iter(move || {
        let init = NoiseParams::new(BaseChoice::Noise,
                                    HandshakePattern::NN,
                                    DHChoice::Curve25519,
                                    CipherChoice::ChaChaPoly,
                                    HashChoice::SHA256);
        NoiseBuilder::new(init)
            .build_initiator().unwrap();
    });
}

#[bench]
fn bench_new_builder_from_params_with_key(b: &mut Bencher) {
    let static_i:Dh25519 = Default::default();
    let privkey = static_i.privkey();
    b.iter(move || {
        let init = NoiseParams::new(BaseChoice::Noise,
                                    HandshakePattern::NN,
                                    DHChoice::Curve25519,
                                    CipherChoice::ChaChaPoly,
                                    HashChoice::SHA256);
        NoiseBuilder::new(init)
            .local_private_key(privkey)
            .build_initiator().unwrap();
    });
}