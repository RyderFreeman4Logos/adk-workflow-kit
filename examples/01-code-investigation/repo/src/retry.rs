pub fn default_retry() -> u8 {
    // Default retry path: three attempts.
    retry_with_limit(3)
}

pub fn retry_with_limit(limit: u8) -> u8 {
    limit
}

pub fn bypass_retry() -> u8 {
    // Bypass path intentionally skips the retry helper.
    0
}

#[cfg(feature = "fast-retry")]
pub fn feature_gated_bypass() -> u8 {
    // Feature-gated bypass is not part of the default build.
    0
}

pub fn misleading_retry_name() -> &'static str {
    "not a retry implementation"
}

fn dead_code_helper() -> u8 {
    99
}

#[cfg(test)]
fn test_only_helper() -> u8 {
    7
}
