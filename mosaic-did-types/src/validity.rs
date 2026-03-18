//! Shared validity window logic for DID document elements.
//!
//! Both off-chain (`VerificationMethod`, `RightGrant`) and on-chain
//! (`OnChainVerificationMethod`, `OnChainRightGrant`) types delegate
//! their temporal validity checks to this single implementation.

/// Check whether a block `height` falls within an active validity window.
///
/// A window is active when:
/// - `height >= start` (element has been created)
/// - `height < expires` (if an expiry is set)
/// - `height < revoked` (if revocation has occurred)
#[inline]
pub fn is_height_valid(
    height: u32, start: u32, expires_at: Option<u32>, revoked_at: Option<u32>,
) -> bool {
    if height < start {
        return false;
    }
    if let Some(expires) = expires_at {
        if height >= expires {
            return false;
        }
    }
    if let Some(revoked) = revoked_at {
        if height >= revoked {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn before_start_is_invalid() {
        assert!(!is_height_valid(9, 10, None, None));
    }

    #[test]
    fn at_start_is_valid() {
        assert!(is_height_valid(10, 10, None, None));
    }

    #[test]
    fn no_bounds_stays_valid() {
        assert!(is_height_valid(1_000_000, 1, None, None));
    }

    #[test]
    fn expires_at_boundary() {
        assert!(is_height_valid(99, 10, Some(100), None));
        assert!(!is_height_valid(100, 10, Some(100), None));
    }

    #[test]
    fn revoked_at_boundary() {
        assert!(is_height_valid(49, 10, None, Some(50)));
        assert!(!is_height_valid(50, 10, None, Some(50)));
    }

    #[test]
    fn expires_and_revoked_earliest_wins() {
        // Revoked before expiry
        assert!(!is_height_valid(50, 10, Some(100), Some(50)));
        // Expired before revocation
        assert!(!is_height_valid(80, 10, Some(80), Some(100)));
    }
}
