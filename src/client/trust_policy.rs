use std::collections::HashSet;

/// Explicit policy for trusting self-signed LocalSend peer certificates.
///
/// `TlsTrustPolicy::new(fingerprints)` accepts only the listed
/// SHA-256 fingerprints and rejects everything else.
///
/// `TlsTrustPolicy::insecure()` preserves the historical accept-all behavior
/// and is intended for development and ad-hoc LAN debugging. Production code
/// should construct a policy from a trusted fingerprint store.
#[derive(Debug, Clone)]
pub struct TlsTrustPolicy {
    trusted: Option<HashSet<String>>,
}

impl TlsTrustPolicy {
    pub fn new<I, S>(trusted: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            trusted: Some(trusted.into_iter().map(Into::into).collect()),
        }
    }

    pub fn insecure() -> Self {
        Self { trusted: None }
    }

    pub fn allows(&self, fingerprint: &str) -> bool {
        match &self.trusted {
            None => true,
            Some(set) => !fingerprint.trim().is_empty() && set.contains(fingerprint),
        }
    }

    /// Returns `true` when the policy permits connecting to peers that present
    /// an invalid (for example self-signed) certificate. Mirrors the historical
    /// `danger_accept_invalid_certs(true)` semantics for `Insecure` policies.
    pub fn allows_insecure(&self) -> bool {
        self.trusted.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::TlsTrustPolicy;

    #[test]
    fn trust_policy_accepts_matching_fingerprint() {
        let policy = TlsTrustPolicy::new(vec!["trusted-fp".to_string()]);
        assert!(policy.allows("trusted-fp"));
    }

    #[test]
    fn trust_policy_rejects_unknown_fingerprint() {
        let policy = TlsTrustPolicy::new(vec!["trusted-fp".to_string()]);
        assert!(!policy.allows("other-fp"));
    }

    #[test]
    fn trust_policy_rejects_empty_fingerprints() {
        let policy = TlsTrustPolicy::new(vec!["trusted-fp".to_string()]);
        assert!(!policy.allows(""));
    }

    #[test]
    fn trust_policy_insecure_accepts_anything_when_no_fingerprints() {
        let policy = TlsTrustPolicy::insecure();
        assert!(policy.allows(""));
        assert!(policy.allows("unknown-fp"));
    }
}
