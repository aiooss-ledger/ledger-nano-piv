use nanos_sdk::io;
use nanos_sdk::io::StatusWords;
use thiserror_no_std::Error;

#[derive(Error)]
pub enum PIVError {
    #[error("verification failed")]
    VerificationFailed,

    #[error("wrong length (expected {expected:?}, got {actual:?})")]
    WrongLength {
        expected: usize,
        actual: usize,
    },

    #[error("secure messaging not supported")]
    SecureMessagingNotSupported,

    #[error("security status not satisfied")]
    SecurityStatusNotSatisfied,

    #[error("auth method blocked")]
    AuthMethodBlocked,

    #[error("missing secure messaging data")]
    MissingSecureMessagingData,

    #[error("incorrect secure messaging data")]
    IncorrectSecureMessagingData,

    #[error("wrong data")]
    WrongData,

    #[error("func not supported")]
    FuncNotSupported,

    #[error("file not found")]
    FileNotFound,

    #[error("file full")]
    FileFull,

    #[error("first parameter incorrect (expected {expected:02X}, got {actual:02X})")]
    IncorrectP1 {
        expected: u8,
        actual: u8,
    },

    #[error("second parameter incorrect (expected {expected:02X}, got {actual:02X})")]
    IncorrectP2 {
        expected: u8,
        actual: u8,
    },

    #[error("ref data not found")]
    RefDataNotFound,

    #[error("data error")]
    DataError { status: StatusWords },
}

impl From<PIVError> for io::Reply {
    fn from(err: PIVError) -> io::Reply {
        // Status Words as specified in table 6 of Interfaces for Personal Identity
        // Verification specification.
        io::Reply(match err {
            PIVError::VerificationFailed => 0x6300,
            PIVError::WrongLength { .. } => 0x6700,
            PIVError::SecureMessagingNotSupported => 0x6882,
            PIVError::SecurityStatusNotSatisfied => 0x6982,
            PIVError::AuthMethodBlocked => 0x6983,
            PIVError::MissingSecureMessagingData => 0x6987,
            PIVError::IncorrectSecureMessagingData => 0x6988,
            PIVError::WrongData => 0x6A80,
            PIVError::FuncNotSupported => 0x6A81,
            PIVError::FileNotFound => 0x6A82,
            PIVError::FileFull => 0x6A84,
            PIVError::IncorrectP1 { .. } | PIVError::IncorrectP2 { .. } => 0x6A86,
            PIVError::RefDataNotFound => 0x6A88,
            PIVError::DataError { status } => status as u16
        })
    }
}
