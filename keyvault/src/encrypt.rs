//! A thin integration of `Argon2i` and `XChaCha20Poly1305` algorithms from the `orion` crate to encrypt/decrypt in-memory blobs with a password.

use orion::aead::SecretKey;

use super::*;
use crate::error::KeyvaultError;

fn password_to_key(pw: &str, salt: &[u8]) -> Result<SecretKey> {
    use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
    use orion::kdf::{Password, Salt, derive_key};

    let pw = Password::from_slice(pw.as_bytes()).map_err(|_| KeyvaultError::PasswordTooShort)?;
    let salt = Salt::from_slice(salt).map_err(|_| KeyvaultError::SaltTooShort)?;
    let kdf_key = derive_key(&pw, &salt, 15, 1024, CHACHA_KEYSIZE as u32)
        .map_err(|_| KeyvaultError::KeyDerivationFailed)?;
    let key = SecretKey::from_slice(kdf_key.unprotected_as_bytes())
        .map_err(|_| KeyvaultError::KeyConversionFailed)?;
    Ok(key)
}

/// Generates a 24-byte random nonce that can be used with the [`encrypt()`] function.
///
/// # Errors
///
/// When the underlying platform is unable to provide enough random entropy.
pub fn nonce() -> Result<[u8; 24]> {
    let mut result = [0u8; 24];
    getrandom::fill(&mut result)?;
    Ok(result)
}

/// Encrypts the plaintext with a password. Make sure the password is not weak. Make sure to generate an exactly 24-byte random nonce for each call
/// otherwise there is a chance of weakening the key if the same nonce is used more than once. The ciphertext returned will be 40 bytes longer than the
/// plaintext.
pub fn encrypt(
    plaintext: impl AsRef<[u8]>, pw: impl AsRef<str>, nonce: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    use orion::hazardous::{
        aead::xchacha20poly1305::{Nonce, SecretKey as XSecretKey, seal},
        mac::poly1305::POLY1305_OUTSIZE,
        stream::xchacha20::XCHACHA_NONCESIZE,
    };
    let plaintext = plaintext.as_ref();
    let pw = pw.as_ref();
    let nonce = nonce.as_ref();

    let key = password_to_key(pw, nonce)?;
    let key = XSecretKey::from_slice(key.unprotected_as_bytes())
        .map_err(|_| KeyvaultError::InvalidKey)?;

    let nonce = Nonce::from_slice(nonce).map_err(|_| KeyvaultError::NonceTooShort)?;

    let out_len = match plaintext.len().checked_add(XCHACHA_NONCESIZE + POLY1305_OUTSIZE) {
        Some(min_out_len) => min_out_len,
        None => return Err(KeyvaultError::PlaintextTooLong),
    };
    let mut output = vec![0u8; out_len];
    output[..XCHACHA_NONCESIZE].copy_from_slice(nonce.as_ref());

    seal(&key, &nonce, plaintext, None, &mut output[XCHACHA_NONCESIZE..])
        .map_err(|_| KeyvaultError::KeyConversionFailed)?;

    Ok(output)
}

/// Decrypts the ciphertext with a password. The format of the ciphertext is defined by the [`encrypt()`] function. Only the matching
/// password will decrypt the ciphertext.
pub fn decrypt(ciphertext: impl AsRef<[u8]>, pw: impl AsRef<str>) -> Result<Vec<u8>> {
    use orion::aead::open;
    use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;

    let ciphertext = ciphertext.as_ref();
    let pw = pw.as_ref();

    if ciphertext.len() <= XCHACHA_NONCESIZE {
        return Err(KeyvaultError::CiphertextTooShort);
    }

    let key = password_to_key(pw, &ciphertext[..XCHACHA_NONCESIZE])?;
    open(&key, ciphertext).map_err(|_| KeyvaultError::CiphertextTampered)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_test_vector() -> Result<()> {
        let nonce = hex::decode(b"55287edc4265bdd919532b93dc0d4854b36b5d5a3c979384")?;
        let password = "password123";
        let plaintext = b"Be at the big tree at 5pm tomorrow!";
        let ciphertext = encrypt(plaintext, password, &nonce)?;

        assert_eq!(ciphertext.len(), plaintext.len() + 40);
        assert_eq!(
            hex::encode(ciphertext),
            "55287edc4265bdd919532b93dc0d4854b36b5d5a3c979384f7e4e8cf7af1f0b5d0d2df2d08fb2d5039d4108f2d5c37643cb0d72c13d07c7b7c9485cfbae8923c594c2134f389ba19ae240e"
        );

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<()> {
        let nonce = nonce()?;

        let password = "password123";
        let message = "Be at the big tree at 5pm tomorrow!";
        let plaintext = message.as_bytes().to_owned();
        let ciphertext = encrypt(&plaintext, password, nonce)?;
        let plaintext2 = decrypt(&ciphertext, password)?;

        assert_eq!(&plaintext2, &plaintext);
        assert_eq!(message.len(), 35);
        assert_eq!(ciphertext.len(), 35 + 40);

        Ok(())
    }
}
