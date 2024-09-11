use primitive_types::U256;
use std::cmp::Ordering;
use std::ops::{Div, Neg, Rem};

#[derive(Debug, PartialEq, PartialOrd, Eq, Copy, Clone)]
pub struct I256(pub U256);

impl I256 {
    pub fn zero() -> I256 {
        I256(U256::zero())
    }

    pub fn one() -> I256 {
        I256(U256::one())
    }

    pub fn min() -> I256 {
        I256(U256::one() << 255)
    }

    pub fn max() -> I256 {
        I256(!(U256::one() << 255))
    }
}

impl I256 {
    pub fn is_zero(&self) -> bool {
        self.0 == U256::zero()
    }

    pub fn is_negative_one(&self) -> bool {
        self.0 == !U256::zero()
    }

    pub fn sign(&self) -> i32 {
        if self.0 == U256::zero() {
            0
        } else if self.0 & (U256::one() << 255) > U256::zero() {
            -1
        } else {
            1
        }
    }
}

impl From<U256> for I256 {
    fn from(value: U256) -> Self {
        Self(value)
    }
}

impl From<i32> for I256 {
    fn from(value: i32) -> Self {
        let positive = value * -1;
        I256::from(U256::from(positive)).neg()
    }
}

impl Ord for I256 {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.sign(), other.sign()) {
            (0, 0) => Ordering::Equal,
            (0, 1) => Ordering::Less,
            (0, -1) => Ordering::Greater,
            (1, 0) => Ordering::Greater,
            (1, -1) => Ordering::Greater,
            (1, 1) => self.0.cmp(&other.0),
            (-1, 0) => Ordering::Less,
            (-1, 1) => Ordering::Less,
            (-1, -1) => self.0.cmp(&other.0).reverse(),
            _ => Ordering::Equal,
        }
    }
}

impl From<I256> for U256 {
    fn from(value: I256) -> Self {
        value.0
    }
}

impl Neg for I256 {
    type Output = I256;

    fn neg(self) -> Self::Output {
        // two's complement of self
        (!self.0 + U256::one()).into()
    }
}

impl Div for I256 {
    type Output = I256;

    fn div(self, other: Self) -> Self::Output {
        // deal with exceptions
        if other.is_zero() {
            return I256::zero();
        }

        // convert number to positivie for all negative numbers and perform binary.
        let mut lhs = self.clone();
        let mut rhs = other.clone();
        if self.sign() < 0 {
            lhs = lhs.neg();
        }

        if rhs.sign() < 0 {
            rhs = rhs.neg();
        }

        let raw = lhs.0 / rhs.0;
        let result = I256::from(raw);

        // if signs are diff, return negative, otherwise positive or zero
        if self.sign() != other.sign() {
            // negate
            return result.neg();
        }

        result
    }
}

impl Rem for I256 {
    type Output = I256;

    fn rem(self, rhs: Self) -> Self::Output {
        // use positives only
        let mut lhs_val = self.clone();
        let mut rhs_val = rhs.clone();

        if lhs_val.sign() < 0 {
            lhs_val = lhs_val.neg()
        }
        if rhs_val.sign() < 0 {
            rhs_val = rhs_val.neg()
        }

        let mut raw = lhs_val.0 % rhs_val.0;
        if self.sign() < 0 || rhs.sign() < 0 {
            raw = rhs.0 - raw;
        }

        I256::from(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rem_impl() {
        let a = I256::one();
        let b = I256::one();
        assert_eq!(a % b, I256::zero());

        let a = I256::from(U256::from(11));
        let b = I256::from(U256::from(7));
        assert_eq!(a % b, I256::from(U256::from(4)));

        // -11 % 7
        let a = I256::from(U256::from(11)).neg();
        let b = I256::from(U256::from(7));
        assert_eq!(a % b, I256::from(U256::from(3)));
    }

    #[test]
    fn div_impl() {
        let a = I256::one();
        let b = I256::one();
        assert_eq!(a / b, I256::one());

        let a = I256::from(U256::from(6));
        let b = I256::from(U256::from(2));
        assert_eq!(a / b, I256::from(U256::from(3)));

        let a = I256::from(U256::from(5));
        let b = I256::from(U256::from(2));
        assert_eq!(a / b, I256::from(U256::from(2)));

        let a = I256::from(U256::from(15));
        let b = I256::from(U256::from(5));
        assert_eq!(a / b, I256::from(U256::from(3)));

        // -1 / -1 = +1
        let a = I256::from(U256::MAX);
        let b = I256::from(U256::MAX);
        let c = a / b;
        assert_eq!(c.sign(), 1);
        assert_eq!(a / b, I256::from(U256::one()));

        // 5 / -1 = -5
        let a = I256::from(U256::from(5));
        let b = I256::from(U256::MAX);
        let c = a / b;
        assert_eq!(c.sign(), -1);
    }

    #[test]
    fn from_u256() {
        let a = U256::from(123);
        let b: I256 = a.into();

        // assert_eq!(a, b);
    }

    #[test]
    fn zed() {
        let zero = I256::zero();
        assert_eq!(zero.sign(), 0);
        assert_eq!(zero.0, U256::zero());
    }

    #[test]
    fn get_sign() {
        // zero
        let num = I256(U256::zero());
        assert_eq!(num.sign(), 0);

        // posivites
        let num = I256(U256::one());
        assert_eq!(num.sign(), 1);
        let num = I256(U256::from(123));
        assert_eq!(num.sign(), 1);

        // negatives
        let num = I256(U256::one() << 255);
        assert_eq!(num.sign(), -1);

        let num = I256(!U256::zero());
        assert_eq!(num.sign(), -1);
    }
}
