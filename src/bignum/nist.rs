use super::Bignum;

pub const NIST_P: Bignum<24> = Bignum {
    limbs: [
        0xffffffffffffffff,
        0xf1746c08ca237327,
        0x670c354e4abc9804,
        0x9ed529077096966d,
        0x1c62f356208552bb,
        0x83655d23dca3ad96,
        0x69163fa8fd24cf5f,
        0x98da48361c55d39a,
        0xc2007cb8a163bf05,
        0x49286651ece45b3d,
        0xae9f24117c4b1fe6,
        0xee386bfb5a899fa5,
        0xbff5cb6f406b7ed,
        0xf44c42e9a637ed6b,
        0xe485b576625e7ec6,
        0x4fe1356d6d51c245,
        0x302b0a6df25f1437,
        0xef9519b3cd3a431b,
        0x514a08798e3404dd,
        0x20bbea63b139b22,
        0x29024e088a67cc74,
        0xc4c6628b80dc1cd1,
        0xc90fdaa22168c234,
        0xffffffffffffffff,
    ],
};

pub const NIST_G: Bignum<24> = {
    let mut limbs = [0u64; 24];
    limbs[0] = 2;
    Bignum { limbs }
};
