use num_bigint::{BigUint, RandBigInt};
use rand::Rng;

pub struct ZKP {
    pub alpha: BigUint,
    pub beta: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

impl ZKP {
    pub fn new() -> Self {
        let (alpha, beta, p, q) = Self::get_constants();
        ZKP { alpha, beta, p, q }
    }

    pub fn compute_pair(&self, exp: &BigUint) -> (BigUint, BigUint) {
        let a = self.alpha.modpow(exp, &self.p);
        let b = self.beta.modpow(exp, &self.p);
        (a, b)
    }

    pub fn solve(
        &self,
        k: &BigUint,
        c: &BigUint,
        x: &BigUint
    ) -> BigUint {
        let res = (c * x) % &self.q;
        (k + &self.q - res) % &self.q
    }

    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        let cond1 = *r1
            == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        let cond2 = *r2
            == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        cond1 && cond2
    }

    pub fn generate_random_number_below(limit: &BigUint) -> BigUint {
        let mut r = rand::thread_rng();
        r.gen_biguint_below(limit)
    }

    pub fn generate_random_string(size: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";

        let mut rng = rand::thread_rng();
        (0..size)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    pub fn get_constants() -> (BigUint, BigUint, BigUint, BigUint) {
        let p = BigUint::from_bytes_be(
            &hex::decode(
                "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B6160\
                 73E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACC\
                 BDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151A\
                 F5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
            )
            .unwrap(),
        );

        let q = BigUint::from_bytes_be(
            &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap(),
        );

        let alpha = BigUint::from_bytes_be(
            &hex::decode(
                "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D312\
                 66FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7F\
                 BD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4\
                 D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
            )
            .unwrap(),
        );

        let exp = BigUint::from_bytes_be(&hex::decode("266FEA1E5C41564B777E69").unwrap());

        let beta = alpha.modpow(&exp, &p);

        (alpha, beta, p, q)
    }
}
