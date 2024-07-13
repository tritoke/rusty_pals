#![allow(non_snake_case)]

use std::rc::Rc;

use crypto_core::bignum::nist::{NIST_G, NIST_P};
use crypto_core::bignum::{Bignum, MontyForm, MontyInfo};
use crypto_core::crypto::aes::Aes128;
use crypto_core::crypto::shs::Sha1;
use crypto_core::crypto::Hasher as _;
use crypto_core::rand::{Rng32, XorShift32};
use crypto_core::util::cast_as_array;

type U1536 = Bignum<24>;
type Context = Rc<MontyInfo<24>>;
type M1536 = MontyForm<24>;

#[derive(Debug, Clone)]
struct Group {
    generator: M1536,
    context: Context,
}

struct KeyPair {
    private: U1536,
    public: M1536,
}

impl Group {
    fn gen_keypair(&self, rng: impl Rng32) -> KeyPair {
        let private = U1536::random(rng);
        let public = self.generator.pow(&private);
        KeyPair { private, public }
    }
}

impl Default for Group {
    fn default() -> Self {
        let context = Rc::new(MontyInfo::new(NIST_P));
        let generator = M1536::new(&NIST_G, context.clone());
        Self { generator, context }
    }
}

fn compute_enc_key(shared_key: U1536) -> Aes128 {
    let mut hasher = Sha1::new();
    hasher.update(shared_key);
    hasher.finalize();
    let digest = hasher.digest();
    Aes128::new(cast_as_array(&digest.as_ref()[..16]))
}

#[test]
fn challenge33_small() {
    let mut rng = XorShift32::new();

    let p = 37;
    let g = 5;

    let a = rng.gen() % p;
    let b = rng.gen() % p;

    // bootleg modexp
    fn modexp(x: u32, e: u32, p: u32) -> u32 {
        let mut X = x;
        for _ in 0..e {
            X = X * x % p;
        }
        X
    }

    let A = modexp(g, a, p);
    let B = modexp(g, b, p);

    let s_a = modexp(A, b, p);
    let s_b = modexp(B, a, p);

    assert_eq!(s_a, s_b);
}

#[test]
fn challenge33_big() {
    let mut rng = XorShift32::new();
    let group = Group::default();

    let KeyPair {
        private: a,
        public: A,
    } = group.gen_keypair(&mut rng);
    let KeyPair {
        private: b,
        public: B,
    } = group.gen_keypair(&mut rng);

    let K_a = B.pow(&a);
    let K_b = A.pow(&b);

    assert_eq!(K_a, K_b);
}

mod chall34 {
    use crypto_core::crypto::{
        aes::{self, Aes, Iv},
        pad::{pkcs7, pkcs7_unpad_owned},
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct Initial {
        pub_key: M1536,
        group: Group,
    }

    #[derive(Debug, Clone)]
    struct ResponsePublicKey {
        key: M1536,
    }

    #[derive(Debug, Clone)]
    struct EncMessage {
        iv: Iv,
        message: Vec<u8>,
    }

    trait Party {
        fn new(rng: impl Rng32) -> Self;

        fn init(&mut self) -> Initial;
        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey;
        fn recv_pub(&mut self, resp_pub: ResponsePublicKey);

        fn enc(&self, msg: &[u8]) -> EncMessage;
        fn dec(&self, enc_msg: EncMessage) -> Vec<u8>;
    }

    struct Honest {
        priv_key: U1536,
        shared_secret: Option<Aes128>,
    }

    impl Party for Honest {
        fn new(rng: impl Rng32) -> Self {
            let priv_key = U1536::random(rng);

            Self {
                priv_key,
                shared_secret: None,
            }
        }

        fn init(&mut self) -> Initial {
            let group = Group::default();
            Initial {
                pub_key: group.generator.pow(&self.priv_key),
                group,
            }
        }

        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey {
            let pub_key = init.group.generator.pow(&self.priv_key);
            let shared_key = init.pub_key.pow(&self.priv_key);

            self.shared_secret = Some(compute_enc_key(shared_key.into()));

            ResponsePublicKey { key: pub_key }
        }

        fn recv_pub(&mut self, resp_pub: ResponsePublicKey) {
            let shared_key = resp_pub.key.pow(&self.priv_key);

            self.shared_secret = Some(compute_enc_key(shared_key.into()));
        }

        fn enc(&self, msg: &[u8]) -> EncMessage {
            let mut rng = XorShift32::new();

            let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
            let iv = Iv::Block(rng.gen_array());
            let enc = aes::encrypt(padded, self.shared_secret.unwrap(), iv, aes::Mode::CBC);

            EncMessage { iv, message: enc }
        }

        fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
            let EncMessage { iv, message: enc } = enc_msg;

            let mut dec = aes::decrypt(enc, self.shared_secret.unwrap(), iv, aes::Mode::CBC);
            pkcs7_unpad_owned(&mut dec).unwrap();
            dec
        }
    }

    struct Malicious {
        key: Aes128,
    }

    impl Party for Malicious {
        fn new(_rng: impl Rng32) -> Self {
            Self {
                key: compute_enc_key(U1536::ZERO),
            }
        }

        fn init(&mut self) -> Initial {
            let group = Group::default();
            Initial {
                pub_key: M1536::new(&Bignum::ZERO, group.context.clone()),
                group,
            }
        }

        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey {
            ResponsePublicKey {
                key: M1536::new(&Bignum::ZERO, init.group.context),
            }
        }

        fn recv_pub(&mut self, _resp: ResponsePublicKey) {}

        fn enc(&self, msg: &[u8]) -> EncMessage {
            let mut rng = XorShift32::new();

            let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
            let iv = Iv::Block(rng.gen_array());
            let enc = aes::encrypt(padded, self.key, iv, aes::Mode::CBC);

            EncMessage { iv, message: enc }
        }

        fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
            let EncMessage { iv, message: enc } = enc_msg;

            let mut dec = aes::decrypt(enc, self.key, iv, aes::Mode::CBC);
            pkcs7_unpad_owned(&mut dec).unwrap();
            dec
        }
    }

    fn diffie_hellman<A: Party, B: Party>(msg: &[u8], mut rng: impl Rng32) {
        let mut a = A::new(&mut rng);
        let mut b = B::new(&mut rng);

        let init = a.init();
        let resp = b.resp_pub(init);
        a.recv_pub(resp);

        let a_to_a = a.dec(a.enc(msg));
        let a_to_b = a.dec(b.enc(msg));
        let b_to_a = b.dec(a.enc(msg));
        let b_to_b = b.dec(b.enc(msg));

        assert_eq!(a_to_a, msg);
        assert_eq!(a_to_b, msg);
        assert_eq!(b_to_a, msg);
        assert_eq!(b_to_b, msg);
    }

    fn mitm<A: Party, B: Party, M: Party>(msg: &[u8], mut rng: impl Rng32) {
        let mut a = A::new(&mut rng);
        let mut b = B::new(&mut rng);
        let mut m = M::new(&mut rng);

        let a_init = a.init();
        let m_init = m.init();

        let m_resp = m.resp_pub(a_init);
        a.recv_pub(m_resp);

        let b_resp = b.resp_pub(m_init);
        m.recv_pub(b_resp);

        let a_enc = a.enc(msg);
        let m_dec = m.dec(a_enc.clone());
        let b_dec = b.dec(a_enc);

        assert_eq!(m_dec, msg);
        assert_eq!(b_dec, msg);
    }

    #[test]
    fn challenge34() {
        let mut rng = XorShift32::new();

        diffie_hellman::<Honest, Honest>(b"My name is jeff and I love to eat socks", &mut rng);
        mitm::<Honest, Honest, Malicious>(b"My name is socks and I love to eat jeff", &mut rng);
    }
}

mod chall35 {
    use crypto_core::crypto::{
        aes::{self, Aes, Aes128, Iv},
        pad::{pkcs7, pkcs7_unpad_owned},
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct Ack;

    #[derive(Debug, Clone)]
    struct ResponsePublicKey {
        key: M1536,
    }

    #[derive(Debug, Clone)]
    struct EncMessage {
        iv: Iv,
        message: Vec<u8>,
    }

    trait Party {
        fn new(rng: impl Rng32) -> Self;

        fn init(&mut self) -> Group;
        fn ack(&mut self, group: Group) -> Ack;
        fn send_pub(&mut self, ack: Ack) -> ResponsePublicKey;
        fn reply_pub(&mut self, resp_pub: ResponsePublicKey) -> ResponsePublicKey;
        fn recv_pub(&mut self, resp_pub: ResponsePublicKey);

        fn enc(&self, msg: &[u8]) -> EncMessage;
        fn dec(&self, enc_msg: EncMessage) -> Vec<u8>;
    }

    struct Honest {
        priv_key: U1536,
        group: Group,
        shared_secret: Option<Aes128>,
    }

    impl Party for Honest {
        fn new(rng: impl Rng32) -> Self {
            let priv_key = U1536::random(rng);

            Self {
                priv_key,
                group: Group::default(),
                shared_secret: None,
            }
        }

        fn init(&mut self) -> Group {
            self.group.clone()
        }

        fn ack(&mut self, init: Group) -> Ack {
            self.group = init;

            Ack
        }

        fn send_pub(&mut self, _ack: Ack) -> ResponsePublicKey {
            let pub_key = self.group.generator.pow(&self.priv_key);

            ResponsePublicKey { key: pub_key }
        }

        fn reply_pub(&mut self, resp_pub: ResponsePublicKey) -> ResponsePublicKey {
            let shared_key = resp_pub.key.pow(&self.priv_key);
            self.shared_secret = Some(compute_enc_key(shared_key.into()));

            let pub_key = self.group.generator.pow(&self.priv_key);

            ResponsePublicKey { key: pub_key }
        }

        fn recv_pub(&mut self, resp_pub: ResponsePublicKey) {
            let shared_key = resp_pub.key.pow(&self.priv_key);
            self.shared_secret = Some(compute_enc_key(shared_key.into()));
        }

        fn enc(&self, msg: &[u8]) -> EncMessage {
            let mut rng = XorShift32::new();

            let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
            let iv = Iv::Block(rng.gen_array());
            let enc = aes::encrypt(padded, self.shared_secret.unwrap(), iv, aes::Mode::CBC);

            EncMessage { iv, message: enc }
        }

        fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
            let EncMessage { iv, message: enc } = enc_msg;

            let mut dec = aes::decrypt(enc, self.shared_secret.unwrap(), iv, aes::Mode::CBC);
            pkcs7_unpad_owned(&mut dec).unwrap();
            dec
        }
    }

    struct Malicious<const G: i8> {
        group: Group,
        pub_key: M1536,
        key: Aes128,
    }

    impl<const G: i8> Party for Malicious<G> {
        fn new(_rng: impl Rng32) -> Self {
            let mut group = Group::default();
            let generator = match G {
                -1 => *group.context.modulus() - Bignum::ONE,
                0 => Bignum::ZERO,
                1 => Bignum::ONE,
                _ => unreachable!("Invalid value for G: {G}, valid values are -1, 0, 1"),
            };
            group.generator = MontyForm::new(&generator, group.context.clone());

            let pub_key = if G == 0 {
                MontyForm::new(&Bignum::ZERO, group.context.clone())
            } else {
                MontyForm::new(&Bignum::ONE, group.context.clone())
            };

            let key = compute_enc_key(pub_key.clone().into());
            Self {
                group,
                pub_key,
                key,
            }
        }

        fn init(&mut self) -> Group {
            self.group.clone()
        }

        fn ack(&mut self, _init: Group) -> Ack {
            Ack
        }

        fn send_pub(&mut self, _ack: Ack) -> ResponsePublicKey {
            ResponsePublicKey {
                key: self.pub_key.clone(),
            }
        }

        fn reply_pub(&mut self, resp_pub: ResponsePublicKey) -> ResponsePublicKey {
            if G == -1 {
                self.key = compute_enc_key(resp_pub.key.into());
            }
            ResponsePublicKey {
                key: self.group.generator.clone(),
            }
        }

        fn recv_pub(&mut self, _resp_pub: ResponsePublicKey) {}

        fn enc(&self, msg: &[u8]) -> EncMessage {
            let mut rng = XorShift32::new();

            let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
            let iv = Iv::Block(rng.gen_array());
            let enc = aes::encrypt(padded, self.key, iv, aes::Mode::CBC);

            EncMessage { iv, message: enc }
        }

        fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
            let EncMessage { iv, message: enc } = enc_msg;

            let mut dec = aes::decrypt(enc, self.key, iv, aes::Mode::CBC);
            pkcs7_unpad_owned(&mut dec).unwrap();
            dec
        }
    }

    fn diffie_hellman<A: Party, B: Party>(msg: &[u8], mut rng: impl Rng32) {
        let mut a = A::new(&mut rng);
        let mut b = B::new(&mut rng);

        let init = a.init();
        let ack = b.ack(init);
        let a_pub = a.send_pub(ack);
        let b_pub = b.reply_pub(a_pub);
        a.recv_pub(b_pub);

        let a_to_a = a.dec(a.enc(msg));
        let a_to_b = a.dec(b.enc(msg));
        let b_to_a = b.dec(a.enc(msg));
        let b_to_b = b.dec(b.enc(msg));

        assert_eq!(a_to_a, msg);
        assert_eq!(a_to_b, msg);
        assert_eq!(b_to_a, msg);
        assert_eq!(b_to_b, msg);
    }

    fn mitm<H: Party, M: Party>(msg: &[u8], mut rng: impl Rng32) {
        let mut a = H::new(&mut rng);
        let mut b = H::new(&mut rng);

        // malicious side has two parts:
        // ma: an honest party for talking to A
        // mb: a malicious party who fixes the group for talking to B
        let mut ma = H::new(&mut rng);
        let mut mb = M::new(&mut rng);

        let ma_ack = ma.ack(a.init());
        let b_ack = b.ack(mb.init());

        let a_pub = a.send_pub(ma_ack);
        let mb_pub = mb.send_pub(b_ack);

        let ma_pub = ma.reply_pub(a_pub);
        let b_pub = b.reply_pub(mb_pub);

        a.recv_pub(ma_pub);
        mb.recv_pub(b_pub);

        let a_enc = a.enc(msg);
        let ma_dec = ma.dec(a_enc);
        assert_eq!(ma_dec, msg);

        let mb_enc = mb.enc(msg);
        let b_dec = b.dec(mb_enc);
        assert_eq!(b_dec, msg);

        let b_enc = b.enc(msg);
        let mb_dec = mb.dec(b_enc);
        assert_eq!(mb_dec, msg);

        let ma_enc = ma.enc(msg);
        let a_dec = a.dec(ma_enc);
        assert_eq!(a_dec, msg);
    }

    #[test]
    fn challenge35() {
        let mut rng = XorShift32::new();

        diffie_hellman::<Honest, Honest>(b"My name is jeff and I love to eat socks", &mut rng);
        mitm::<Honest, Malicious<-1>>(b"My name is socks and I love to eat jeff", &mut rng);
        mitm::<Honest, Malicious<0>>(b"My name is socks and I love to eat jeff", &mut rng);
        mitm::<Honest, Malicious<1>>(b"My name is socks and I love to eat jeff", &mut rng);
    }
}

mod chall36 {
    use std::fmt::Write as _;

    use crypto_core::crypto::{
        hmac::Hmac,
        shs::{Sha256, Sha256Digest},
        Hasher,
    };

    use super::*;

    pub type Salt = [u8; 16];

    pub const IDENTITY: &[u8] = b"jeffery.bezos@feetfinder.com";
    pub const PASSWORD: &[u8] = b"I lovveeeee socks";

    pub struct SrpServer {
        salt: Salt,
        verifier: M1536,
        shared_key: Option<Sha256Digest>,
    }

    pub fn digest_to_bignum(digest: Sha256Digest) -> U1536 {
        let mut s = String::new();
        for word in digest.0 {
            write!(&mut s, "{word:08x}").unwrap();
        }

        s.parse().expect("Failed to parse hex as number?")
    }

    impl SrpServer {
        pub fn new() -> Self {
            let group = Group::default();
            let salt = XorShift32::new().gen_array();

            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(PASSWORD);
            hasher.finalize();

            let xH = hasher.digest();
            let x = digest_to_bignum(xH);
            let verifier = group.generator.pow(&x);

            Self {
                salt,
                verifier,
                shared_key: None,
            }
        }

        pub fn recv_pub(
            &mut self,
            identity: impl AsRef<[u8]>,
            client_pub: M1536,
        ) -> Option<(Salt, M1536)> {
            if identity.as_ref() != IDENTITY {
                return None;
            }

            let group = Group::default();
            let ephemeral = group.gen_keypair(XorShift32::new());

            let mut b_pub = MontyForm::new(&Bignum::from(3u64), self.verifier.info());
            b_pub *= &self.verifier;
            b_pub += ephemeral.public;

            let mut hasher = Sha256::new();
            hasher.update(client_pub.inner());
            hasher.update(b_pub.inner());
            hasher.finalize();

            let u = digest_to_bignum(hasher.digest());
            let secret_key = (client_pub * self.verifier.pow(&u)).pow(&ephemeral.private);
            hasher.reset();
            hasher.update(secret_key.inner());
            hasher.finalize();

            self.shared_key = Some(hasher.digest());

            Some((self.salt, b_pub))
        }

        pub fn validate_hmac(&self, mac: Sha256Digest) -> bool {
            let hmac: Hmac<Sha256> = Hmac::new(self.shared_key.unwrap());
            hmac.mac(self.salt) == mac
        }
    }

    struct SrpClient {
        keypair: KeyPair,
        shared_key: Option<Sha256Digest>,
    }

    impl SrpClient {
        fn new() -> Self {
            Self {
                keypair: Group::default().gen_keypair(XorShift32::new()),
                shared_key: None,
            }
        }

        fn send_pub(&self) -> (&[u8], M1536) {
            (IDENTITY, self.keypair.public.clone())
        }

        fn recv_salt(&mut self, salt: Salt, mixed_pub: M1536) -> Sha256Digest {
            let group = Group::default();

            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(PASSWORD);
            hasher.finalize();

            let x = digest_to_bignum(hasher.digest());

            hasher.reset();
            hasher.update(self.keypair.public.inner());
            hasher.update(mixed_pub.inner());
            hasher.finalize();

            let u = digest_to_bignum(hasher.digest());

            let k = MontyForm::new(&Bignum::from(3u64), group.context);
            let secret_key =
                (mixed_pub - (k * group.generator.pow(&x))).pow(&(self.keypair.private + u * x));

            hasher.reset();
            hasher.update(secret_key.inner());
            hasher.finalize();
            let shared_key = hasher.digest();
            self.shared_key = Some(shared_key);

            let hmac: Hmac<Sha256> = Hmac::new(shared_key);
            hmac.mac(salt)
        }
    }

    #[test]
    fn challenge36() {
        let mut server = SrpServer::new();
        let mut client = SrpClient::new();

        let (I, A) = client.send_pub();
        let (salt, B) = server.recv_pub(I, A).expect("Server rejected public key");
        let hmac_K = client.recv_salt(salt, B);

        assert!(server.validate_hmac(hmac_K))
    }
}

mod challenge37 {
    use chall36::Salt;
    use crypto_core::crypto::{
        hmac::Hmac,
        shs::{Sha256, Sha256Digest},
    };

    use super::*;
    use crate::chall36::{SrpServer, IDENTITY};

    struct MaliciousSrpClient {}

    impl MaliciousSrpClient {
        fn new() -> Self {
            Self {}
        }

        fn send_pub(&self) -> (&[u8], M1536) {
            (IDENTITY, M1536::new(&U1536::ZERO, Group::default().context))
        }

        fn recv_salt(&mut self, salt: Salt, _mixed_pub: M1536) -> Sha256Digest {
            let mut hasher = Sha256::new();
            hasher.reset();
            hasher.update(U1536::ZERO);
            hasher.finalize();
            let shared_key = hasher.digest();

            let hmac: Hmac<Sha256> = Hmac::new(shared_key);
            hmac.mac(salt)
        }
    }

    #[test]
    fn challenge37() {
        let mut server = SrpServer::new();
        let mut client = MaliciousSrpClient::new();

        let (I, A) = client.send_pub();
        let (salt, B) = server.recv_pub(I, A).expect("Server rejected public key");
        let hmac_K = client.recv_salt(salt, B);

        assert!(server.validate_hmac(hmac_K))
    }
}

mod challenge38 {
    use chall36::{digest_to_bignum, Salt};
    use crypto_core::crypto::{
        hmac::Hmac,
        shs::{Sha256, Sha256Digest},
    };

    const PASSWORD: &[u8] = b"gg";

    use super::*;
    use crate::chall36::IDENTITY;

    pub struct SimplifiedSrpServer {
        salt: Salt,
        verifier: M1536,
        shared_key: Option<Sha256Digest>,
    }

    impl SimplifiedSrpServer {
        pub fn new() -> Self {
            let group = Group::default();
            let salt = XorShift32::new().gen_array();

            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(PASSWORD);
            hasher.finalize();

            let xH = hasher.digest();
            let x = digest_to_bignum(xH);
            let verifier = group.generator.pow(&x);

            Self {
                salt,
                verifier,
                shared_key: None,
            }
        }

        pub fn recv_pub(
            &mut self,
            identity: impl AsRef<[u8]>,
            client_pub: M1536,
        ) -> Option<(Salt, M1536, U1536)> {
            if identity.as_ref() != IDENTITY {
                return None;
            }

            let group = Group::default();
            let ephemeral = group.gen_keypair(XorShift32::new());

            let mut hasher = Sha256::new();
            hasher.update(XorShift32::new().gen_array::<16>());
            hasher.finalize();
            let u = digest_to_bignum(hasher.digest());

            let secret_key = (client_pub * self.verifier.pow(&u)).pow(&ephemeral.private);
            hasher.reset();
            hasher.update(secret_key.inner());
            hasher.finalize();

            self.shared_key = Some(hasher.digest());

            Some((self.salt, ephemeral.public, u))
        }

        pub fn validate_hmac(&self, mac: Sha256Digest) -> bool {
            let hmac: Hmac<Sha256> = Hmac::new(self.shared_key.unwrap());
            hmac.mac(self.salt) == mac
        }
    }

    struct SimplifiedSrpClient {
        keypair: KeyPair,
        shared_key: Option<Sha256Digest>,
    }

    impl SimplifiedSrpClient {
        fn new() -> Self {
            Self {
                keypair: Group::default().gen_keypair(XorShift32::new()),
                shared_key: None,
            }
        }

        fn send_pub(&self) -> (&[u8], M1536) {
            (IDENTITY, self.keypair.public.clone())
        }

        fn recv_salt(&mut self, salt: Salt, server_pub: M1536, u: U1536) -> Sha256Digest {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(PASSWORD);
            hasher.finalize();

            let x = digest_to_bignum(hasher.digest());

            let secret_key = server_pub.pow(&(self.keypair.private + u * x));

            hasher.reset();
            hasher.update(secret_key.inner());
            hasher.finalize();
            let shared_key = hasher.digest();
            self.shared_key = Some(shared_key);

            let hmac: Hmac<Sha256> = Hmac::new(shared_key);
            hmac.mac(salt)
        }
    }

    #[test]
    fn simplified_srp_works() {
        let mut server = SimplifiedSrpServer::new();
        let mut client = SimplifiedSrpClient::new();

        let (I, A) = client.send_pub();
        let (salt, B, u) = server.recv_pub(I, A).expect("Server rejected public key");
        let hmac_K = client.recv_salt(salt, B, u);

        assert!(server.validate_hmac(hmac_K))
    }

    struct MaliciousSrpServer {
        client_pub: Option<M1536>,
        salt: Salt,
        keypair: KeyPair,
        u: U1536,
    }

    impl MaliciousSrpServer {
        fn new() -> Self {
            let mut rng = XorShift32::new();
            let group = Group::default();

            let mut hasher = Sha256::new();
            hasher.update(XorShift32::new().gen_array::<16>());
            hasher.finalize();
            let u = digest_to_bignum(hasher.digest());

            Self {
                client_pub: None,
                salt: rng.gen_array(),
                keypair: group.gen_keypair(&mut rng),
                u,
            }
        }

        fn recv_pub(
            &mut self,
            _identity: impl AsRef<[u8]>,
            client_pub: M1536,
        ) -> Option<(Salt, M1536, U1536)> {
            self.client_pub = Some(client_pub);

            Some((self.salt, self.keypair.public.clone(), self.u))
        }

        fn recover_password(&self, client_hmac: Sha256Digest) -> Vec<u8> {
            let mut guess: Vec<u8> = vec![];
            let mut hasher = Sha256::new();
            let group = Group::default();

            loop {
                // increment the value of guess
                let mut inc = false;
                for c in guess.iter_mut() {
                    if *c == b'z' {
                        *c = b'a';
                    } else {
                        *c += 1;
                        inc = true;
                        break;
                    }
                }

                if !inc {
                    guess.push(b'a');
                }

                hasher.reset();
                hasher.update(self.salt);
                hasher.update(&guess);
                hasher.finalize();
                let x = digest_to_bignum(hasher.digest());
                let verifier = group.generator.pow(&x);

                let secret_key = (self.client_pub.as_ref().unwrap() * verifier.pow(&self.u))
                    .pow(&self.keypair.private);

                hasher.reset();
                hasher.update(secret_key.inner());
                hasher.finalize();
                let shared_key = hasher.digest();
                let hmac: Hmac<Sha256> = Hmac::new(shared_key);
                if hmac.mac(self.salt) == client_hmac {
                    return guess;
                }
            }
        }
    }

    #[test]
    fn challenge38() {
        let mut server = MaliciousSrpServer::new();
        let mut client = SimplifiedSrpClient::new();

        let (I, A) = client.send_pub();
        let (salt, B, u) = server.recv_pub(I, A).expect("Server rejected public key");
        let hmac_K = client.recv_salt(salt, B, u);

        assert_eq!(server.recover_password(hmac_K), PASSWORD);
    }
}
