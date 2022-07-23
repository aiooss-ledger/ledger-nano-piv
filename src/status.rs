use nanos_sdk::io;

/// Status Words as specified in table 6 of Interfaces for Personal Identity
/// Verification specification.
#[derive(Copy, Clone)]
pub enum StatusWord {
    MoreDataAvailable(u8),
    WrongLength,
    WrongData,
    FuncNotSupported,
    FileNotFound,
    IncorrectP1P2,
    VerificationFailed,
    // SecureMessagingNotSupported = 0x6882,
    // SecurityStatusNotSatisfied = 0x6982,
    // AuthMethodBlocked = 0x6983,
    // MissingSecureMessagingData = 0x6987,
    // IncorrectSecureMessagingData = 0x6988,
    // FileFull = 0x6A84,
    // RefDataNotFound = 0x6A88,
}

impl From<StatusWord> for u16 {
    fn from(val: StatusWord) -> Self {
        match val {
            StatusWord::MoreDataAvailable(size) => 0x6100 + (size as u16),
            StatusWord::WrongLength => 0x6700,
            StatusWord::WrongData => 0x6A80,
            StatusWord::FuncNotSupported => 0x6A81,
            StatusWord::FileNotFound => 0x6A82,
            StatusWord::IncorrectP1P2 => 0x6A86,
            StatusWord::VerificationFailed => 0x6300,
        }
    }
}

impl From<StatusWord> for io::Reply {
    fn from(sw: StatusWord) -> io::Reply {
        io::Reply(sw.into())
    }
}
