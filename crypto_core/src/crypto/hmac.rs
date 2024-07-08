use crate::crypto::Hasher;
use std::marker::PhantomData;

pub struct Hmac<H: Hasher> {
    ipad_key: Vec<u8>,
    opad_key: Vec<u8>,
    _h: PhantomData<H>,
}

impl<H: Hasher> Hmac<H> {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let mut ipad_key = Self::pad_key(key);
        let mut opad_key = ipad_key.clone();

        for (ik, ok) in ipad_key.iter_mut().zip(opad_key.iter_mut()) {
            *ik ^= 0x36;
            *ok ^= 0x5c;
        }

        Self {
            ipad_key,
            opad_key,
            _h: Default::default(),
        }
    }

    fn pad_key(key: impl AsRef<[u8]>) -> Vec<u8> {
        let k = key.as_ref();
        if k.len() > H::BLOCK_SIZE {
            let mut hasher = H::new();
            hasher.update(k);
            hasher.finalize();
            let hashed_key = hasher.digest();
            let pad = std::iter::repeat(0u8)
                .take(H::BLOCK_SIZE.saturating_sub(hashed_key.as_ref().len()));
            let mut key = hashed_key.as_ref().to_vec();
            key.extend(pad);
            key
        } else {
            k.iter()
                .copied()
                .chain(std::iter::repeat(0u8))
                .take(H::BLOCK_SIZE)
                .collect()
        }
    }

    pub fn mac(&self, data: impl AsRef<[u8]>) -> H::Digest {
        let mut ihash = H::new();
        ihash.update(&self.ipad_key);
        ihash.update(data);
        ihash.finalize();

        let mut ohash = H::new();
        ohash.update(&self.opad_key);
        ohash.update(ihash.digest());
        ohash.finalize();
        ohash.digest()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::hmac::Hmac;
    use crate::crypto::shs::Sha1;
    use crate::encoding::Decodable;

    #[test]
    fn rfc2202_test_vector1() {
        let key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
            .decode_hex()
            .unwrap();
        let data = "Hi There";
        let digest = "b617318655057264e28bc0b6fb378c8ef146be00"
            .decode_hex()
            .unwrap();
        let hmac: Hmac<Sha1> = Hmac::new(key);
        let mac = hmac.mac(data);
        assert_eq!(mac.as_ref(), digest.as_slice());
    }

    #[test]
    fn rfc2202_test_vector2() {
        let key = "Jefe";
        let data = "what do ya want for nothing?";
        let digest = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
            .decode_hex()
            .unwrap();
        let hmac: Hmac<Sha1> = Hmac::new(key);
        let mac = hmac.mac(data);
        assert_eq!(mac.as_ref(), digest.as_slice());
    }

    #[test]
    fn rfc2202_test_vector3() {
        let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .decode_hex()
            .unwrap();
        let data = vec![0xdd_u8; 50];
        let digest = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
            .decode_hex()
            .unwrap();
        let hmac: Hmac<Sha1> = Hmac::new(key);
        let mac = hmac.mac(data);
        assert_eq!(mac.as_ref(), digest.as_slice());
    }

    #[test]
    fn rfc2202_test_vector4() {
        let key = "0102030405060708090a0b0c0d0e0f10111213141516171819"
            .decode_hex()
            .unwrap();
        let data = vec![0xcd_u8; 50];
        let digest = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
            .decode_hex()
            .unwrap();
        let hmac: Hmac<Sha1> = Hmac::new(key);
        let mac = hmac.mac(data);
        assert_eq!(mac.as_ref(), digest.as_slice());
    }

    #[test]
    fn rfc2202_test_vector6() {
        let key = vec![0xaa; 80];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let digest = "aa4ae5e15272d00e95705637ce8a3b55ed402112"
            .decode_hex()
            .unwrap();
        let hmac: Hmac<Sha1> = Hmac::new(key);
        let mac = hmac.mac(data);
        assert_eq!(mac.as_ref(), digest.as_slice());
    }

    #[test]
    fn rfc2202_test_vector7() {
        let key = vec![0xaa; 80];
        let data = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        let digest = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
            .decode_hex()
            .unwrap();
        let hmac: Hmac<Sha1> = Hmac::new(key);
        let mac = hmac.mac(data);
        assert_eq!(mac.as_ref(), digest.as_slice());
    }
}
