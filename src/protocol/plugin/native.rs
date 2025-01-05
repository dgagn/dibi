use sha1::Digest;

fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut hasher = sha1::Sha1::default();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result[..20]);
    out
}

pub fn mysql_native_password(password: &[u8], seed: &[u8]) -> [u8; 20] {
    // SHA1( password ) ^ SHA1( seed + SHA1( SHA1( password ) ) )
    let password_hash = sha1_hash(password);
    let hash_pasword_hash = sha1_hash(&password_hash);

    let mut hasher = sha1::Sha1::default();
    hasher.update(seed);
    hasher.update(hash_pasword_hash);
    let result2 = hasher.finalize();
    let hash2 = &result2[..20];

    let mut out = [0u8; 20];
    for (i, (a, b)) in password_hash.iter().zip(hash2.iter()).enumerate() {
        out[i] = a ^ b;
    }

    out
}
