use zeroize::Zeroizing;

use crate::parse_arguments::SecretSource;

pub struct ResolvedSecret {
    pub source: SecretSource,
    pub value: Zeroizing<String>,
}
