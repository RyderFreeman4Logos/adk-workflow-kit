use std::{error::Error, fmt, fs::File, io::Read};

use crate::encode_hex;

/// An opaque session identity for one role in one run.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    /// Returns the lowercase hexadecimal identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A role that receives an independent session identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionRole {
    /// The role that produces run output.
    Producer,
    /// The role that reviews run output.
    Reviewer,
}

/// Independent session identities allocated for one caller-owned run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSessionIds {
    producer: SessionId,
    reviewer: SessionId,
}

impl RunSessionIds {
    /// Allocates independent random identities for the producer and reviewer roles.
    pub fn allocate() -> Result<Self, SessionIdentityError> {
        let mut entropy = File::open("/dev/urandom")
            .map_err(|_| SessionIdentityError::new(SessionIdentityErrorKind::Entropy))?;
        Self::allocate_with(&mut entropy)
    }

    /// Returns the identity allocated for `role`.
    pub fn id(&self, role: SessionRole) -> &SessionId {
        match role {
            SessionRole::Producer => &self.producer,
            SessionRole::Reviewer => &self.reviewer,
        }
    }

    fn allocate_with(reader: &mut impl Read) -> Result<Self, SessionIdentityError> {
        let mut bytes = [0_u8; 32];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| SessionIdentityError::new(SessionIdentityErrorKind::Entropy))?;
        let (producer, reviewer) = bytes.split_at(16);
        if producer == reviewer {
            return Err(SessionIdentityError::new(
                SessionIdentityErrorKind::DuplicateIdentity,
            ));
        }

        Ok(Self {
            producer: SessionId(encode_hex(producer)),
            reviewer: SessionId(encode_hex(reviewer)),
        })
    }
}

/// A stable category for session identity allocation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionIdentityErrorKind {
    /// Random identity bytes could not be obtained.
    Entropy,
    /// Producer and reviewer identity bytes were identical.
    DuplicateIdentity,
}

/// A privacy-safe session identity allocation failure.
#[derive(Debug)]
pub struct SessionIdentityError {
    kind: SessionIdentityErrorKind,
}

impl SessionIdentityError {
    fn new(kind: SessionIdentityErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    pub fn kind(&self) -> SessionIdentityErrorKind {
        self.kind
    }
}

impl fmt::Display for SessionIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            SessionIdentityErrorKind::Entropy => "session identity entropy is unavailable",
            SessionIdentityErrorKind::DuplicateIdentity => {
                "session identity generation produced duplicate role IDs"
            }
        })
    }
}

impl Error for SessionIdentityError {}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    use super::{RunSessionIds, SessionIdentityErrorKind};

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("entropy fixture failure"))
        }
    }

    fn assert_entropy(reader: &mut impl Read) {
        let error = RunSessionIds::allocate_with(reader).expect_err("entropy must fail closed");

        assert_eq!(error.kind(), SessionIdentityErrorKind::Entropy);
        assert_eq!(error.to_string(), "session identity entropy is unavailable");
    }

    #[test]
    fn short_entropy_reader_is_privacy_safe() {
        let mut reader = &b"short"[..];

        assert_entropy(&mut reader);
    }

    #[test]
    fn failing_entropy_reader_is_privacy_safe() {
        assert_entropy(&mut FailingReader);
    }

    #[test]
    fn duplicate_identity_bytes_fail_without_disclosing_ids() {
        let mut reader = &[7_u8; 32][..];
        let error = RunSessionIds::allocate_with(&mut reader)
            .expect_err("identical role identity bytes must fail closed");
        let display = error.to_string();

        assert_eq!(error.kind(), SessionIdentityErrorKind::DuplicateIdentity);
        assert_eq!(
            display,
            "session identity generation produced duplicate role IDs"
        );
        assert!(!display.contains("0707"));
    }
}
