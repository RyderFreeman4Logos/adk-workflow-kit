mod retry;

pub use retry::default_retry;

pub fn run() -> u8 {
    default_retry()
}
