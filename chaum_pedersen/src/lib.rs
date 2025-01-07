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

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    fn new_creates_zkp_with_constants() {
        let zkp = ZKP::new();
        let (alpha, beta, p, q) = ZKP::get_constants();
        assert_eq!(zkp.alpha, alpha);
        assert_eq!(zkp.beta, beta);
        assert_eq!(zkp.p, p);
        assert_eq!(zkp.q, q);
    }

    #[test]
    fn compute_pair_returns_correct_values() {
        let zkp = ZKP::new();
        let exp = BigUint::one();
        let (a, b) = zkp.compute_pair(&exp);
        assert_eq!(a, zkp.alpha.modpow(&exp, &zkp.p));
        assert_eq!(b, zkp.beta.modpow(&exp, &zkp.p));
    }

    #[test]
    fn solve_returns_correct_value() {
        let zkp = ZKP::new();
        let k = BigUint::one();
        let c = BigUint::one();
        let x = BigUint::one();
        let result = zkp.solve(&k, &c, &x);
        assert_eq!(result, (k + &zkp.q - (c * x) % &zkp.q) % &zkp.q);
    }

    #[test]
    fn verify_returns_true_for_valid_inputs() {
        let zkp = ZKP::new();

        // 1) Pick a random secret exponent x
        let x = ZKP::generate_random_number_below(&zkp.q);

        // 2) Compute y1 = alpha^x mod p and y2 = beta^x mod p
        let y1 = zkp.alpha.modpow(&x, &zkp.p);
        let y2 = zkp.beta.modpow(&x, &zkp.p);

        // 3) Pick an ephemeral k
        let k = ZKP::generate_random_number_below(&zkp.q);

        // 4) Compute (r1, r2) = (alpha^k mod p, beta^k mod p)
        let (r1, r2) = zkp.compute_pair(&k);

        // 5) Pick a challenge c
        let c = ZKP::generate_random_number_below(&zkp.q);

        // 6) Compute the response s = k - c*x (mod q)
        let s = zkp.solve(&k, &c, &x);

        // 7) Finally, verify
        assert!(zkp.verify(&r1, &r2, &y1, &y2, &c, &s));
    }

    #[test]
    fn generate_random_number_below_returns_value_below_limit() {
        let limit = BigUint::from(100u32);
        let random_number = ZKP::generate_random_number_below(&limit);
        assert!(random_number < limit);
    }

    #[test]
    fn generate_random_string_returns_string_of_correct_length() {
        let size = 10;
        let random_string = ZKP::generate_random_string(size);
        assert_eq!(random_string.len(), size);
    }
}