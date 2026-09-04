//! Safety numbers: a short fingerprint of two identities that both people can
//! read to each other to confirm nobody sits in between.

use sha2::{Digest, Sha512};

use crate::identity::UserId;

const SAFETY_DOMAIN: &[u8] = b"silver-messenger/v1/safety-number";

/// Sixty decimal digits in twelve groups of five, derived from both identity
/// keys. Symmetric: `safety_number(a, b) == safety_number(b, a)`.
pub fn safety_number(a: &UserId, b: &UserId) -> String {
    let (first, second) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut hasher = Sha512::new();
    hasher.update(SAFETY_DOMAIN);
    hasher.update([0u8]);
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    let digest = hasher.finalize();
    digest
        .chunks(5)
        .take(12)
        .map(|chunk| {
            let value = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn safety_numbers_are_symmetric_and_distinct() {
        let a = Identity::generate().user_id();
        let b = Identity::generate().user_id();
        let c = Identity::generate().user_id();
        let ab = safety_number(&a, &b);
        assert_eq!(ab, safety_number(&b, &a));
        assert_ne!(ab, safety_number(&a, &c));
        let groups: Vec<&str> = ab.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit()))
        );
    }
}
