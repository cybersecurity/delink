use crate::common::DecryptError;
use crate::openssl::{aes_128_cbc_decrypt, MessageDigest};
use log::{debug, warn};
use std::collections::HashMap;

/// Returns a HashMap of known encryption passphrases and their descriptions
pub fn known_keys() -> HashMap<String, String> {
    HashMap::from([
        (
            "044b4e59846ecee953662ff2238fcc23".to_string(),
            "E15 / DAP_X1550 v1.00 - v1.20".to_string(),
        ),
        (
            "927fc5786df1a9557524a0289e1e3f3b".to_string(),
            "E15 / DAP_X1550 > v1.20".to_string(),
        ),
        (
            "4d5ee2c8b5d0fdd9a9a2d351ba897752".to_string(),
            "E30 / DAP_X3020 v1.00 - v1.10".to_string(),
        ),
        (
            "238a29b9432f688e30b701548c753146".to_string(),
            "E30 / DAP_X3020 > v1.10".to_string(),
        ),
        (
            "a4f7c17c3e0aa4532c2024ce6ac5f17c".to_string(),
            "R12 / RC12 v1.00 - v1.10".to_string(),
        ),
        (
            "6b5a65dbc1ebc492ac6d8efbbb59ae09".to_string(),
            "R12 / RC12 > v1.10".to_string(),
        ),
        (
            "70070e579f97548a96a7794d4d779376".to_string(),
            "R15 / DIR_X1550 v1.00 - v1.20".to_string(),
        ),
        (
            "7b4df82f7f042b9d0b40971be0ff53c4".to_string(),
            "R15 / DIR_X1550 > v1.20".to_string(),
        ),
        (
            "6276ccf4c1d8d6f54b481095e78ff97f".to_string(),
            "R18".to_string(),
        ),
        (
            "1ae6c79be7d069ca74df7670bdfc4952".to_string(),
            "M18".to_string(),
        ),
        (
            "b4517d9b98e04d9f075f5e78c743e097".to_string(),
            "M30 v1.02 - v1.10".to_string(),
        ),
        (
            "05c79b73cf88619d7b9725505cfd718f".to_string(),
            "M30 > v1.10".to_string(),
        ),
        (
            "6b29f1d663a21b35fb45b69a42649f5e".to_string(),
            "M32 / AMIT_M2M / AX6000 / COVR_X3260 / R32 / VHG87B_0G018 v1.00 - 1.10".to_string(),
        ),
        (
            "1bfb1004e29f9eb76dbe26eb0dd87cd1".to_string(),
            "M32 / AMIT_M2M / AX6000 / COVR_X3260 / R32 / VHG87B_0G018 > v1.10".to_string(),
        ),
        (
            "c5f8a1e22f808abc84f2e4a6fa5f10bb".to_string(),
            "M60 v1.10".to_string(),
        ),
        (
            "6420da70a975455e4ddd6b8fa5b652e7".to_string(),
            "M60 > v1.10".to_string(),
        ),
        (
            "e5af7b6761f9791b6a522738275002db".to_string(),
            "E12".to_string(),
        ),
        (
            "fa0c50b3d95816b3fffd7da3efd5cb66".to_string(),
            "E18".to_string(),
        ),
        (
            "f23051f55ed058c103c25ec37c6e1601".to_string(),
            "E32".to_string(),
        ),
        (
            "df9c62b095a04e1f67bf4ffe21117eae".to_string(),
            "R03 / RM33".to_string(),
        ),
        (
            "5655840cefb7da085e7c3d9640e64922".to_string(),
            "R04".to_string(),
        ),
        (
            "0bcca591c37f932c839d1eaa4dafc292".to_string(),
            "R18".to_string(),
        ),
        (
            "80c4d262297149e54c04a91bc3329175".to_string(),
            "R36".to_string(),
        ),
        (
            "4e5aad6e440bdd16bdc8b6ad441e47ba".to_string(),
            "R60".to_string(),
        ),
        (
            "08324188e8c509105186636274cf4bea".to_string(),
            "M15 / COVR_X1550 / COVR_X1550_QUICKLINE".to_string(),
        ),
        (
            "b0b2e9efd78ec5dba99e02293c36a94f".to_string(),
            "M36".to_string(),
        ),
        (
            "95d620854d9a51c90ae0a22787f50e17".to_string(),
            "MX32".to_string(),
        ),
        (
            "443a194860796cd9d9a24d99c4242e64".to_string(),
            "G403 / DWR924".to_string(),
        ),
        (
            "118e57f905f0690157f8389b745b6ac8".to_string(),
            "G412".to_string(),
        ),
        (
            "5c67ae65b2329711441a965bc3a73667".to_string(),
            "G413".to_string(),
        ),
        (
            "e1d72a0952b1d349be0b7a32fbd1341e".to_string(),
            "G415 / G415SE / DWR_1953".to_string(),
        ),
        (
            "94706d6f4245039c411af6c3a705e607".to_string(),
            "G416 / G416CP / G416ISP / G416PL / G416TL / DWR_1961".to_string(),
        ),
        (
            "c5ffe41dcdd9518060243921393e7d19".to_string(),
            "G518".to_string(),
        ),
        (
            "29f9ef6781fa478377d9954187fd078b".to_string(),
            "G530".to_string(),
        ),
        (
            "6cc5de3f0022442fe809981fc1f40d4d".to_string(),
            "G560".to_string(),
        ),
        (
            "b40c8b7a06b235471b69591021f82e60".to_string(),
            "B180".to_string(),
        ),
        (
            "ddcada1120056f68738e39d7336630eb".to_string(),
            "B180G".to_string(),
        ),
        (
            "6922920d95a6a48a44d8bf237bea3924".to_string(),
            "B360G".to_string(),
        ),
        (
            "3fb5d73c6ee959edb17ab70f4fb097cf".to_string(),
            "B600".to_string(),
        ),
        (
            "f21247200ea5d552efa08740522d0ff1".to_string(),
            "DVG_X6052 / DVG_X6052ET".to_string(),
        ),
        (
            "0b8073ca811bf3de07a4b79d90cdb49e".to_string(),
            "DIR_X1510".to_string(),
        ),
        (
            "a07e5f355c8f4037a218d791e2d58fa6".to_string(),
            "DIR-LX3260".to_string(),
        ),
    ])
}

/// Decrypt D-Link MH01 firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Encrypted firmware starts with these magic bytes
    const ENCRYPTED_MAGIC: &[u8] = b"MH01";

    // There is a header before the encrypted data
    const HEADER_SIZE: usize = 0x41;

    // Firmware header contains the IV, in ASCII hex
    const IV_START: usize = 32;
    const IV_END: usize = IV_START + 32;

    const ENCRYPTED_DATA_SIZE_FIELD_START: usize = 0x18;
    const ENCRYPTED_DATA_SIZE_FIELD_END: usize = ENCRYPTED_DATA_SIZE_FIELD_START + 4;

    // Expected magic bytes of the decrypted data
    const DECRYPTED_MAGIC: &[u8] = b"MH01";
    const DECRYPTED_MAGIC_START: usize = 0;
    const DECRYPTED_MAGIC_END: usize = DECRYPTED_MAGIC_START + DECRYPTED_MAGIC.len();

    // Validate the encrypted firmware header magic bytes
    if let Some(encrypted_magic) = encrypted_data.get(0..ENCRYPTED_MAGIC.len()) {
        if encrypted_magic == ENCRYPTED_MAGIC {
            // Get the size of the encrypted data
            if let Some(encrypted_size_bytes) =
                encrypted_data.get(ENCRYPTED_DATA_SIZE_FIELD_START..ENCRYPTED_DATA_SIZE_FIELD_END)
            {
                let encrypted_data_size =
                    u32::from_le_bytes(encrypted_size_bytes.try_into().unwrap()) as usize;

                // Calculate the start and end offsets of the encrypted data
                let cipher_data_start: usize = HEADER_SIZE;
                let cipher_data_end: usize = cipher_data_start + encrypted_data_size;

                // Get the IV data (ASCII hex) and decode it
                if let Some(iv_ascii) = encrypted_data.get(IV_START..IV_END) {
                    match hex::decode(iv_ascii) {
                        Err(e) => {
                            debug!("Invalid ASCII IV: {}", e);
                            return Err(DecryptError::Input);
                        }
                        Ok(iv) => {
                            // Get the encrypted data
                            if let Some(cipher_data) =
                                encrypted_data.get(cipher_data_start..cipher_data_end)
                            {
                                // Try to decrypt with known encryption keys
                                let mut sorted_keys: Vec<_> = known_keys().into_iter().collect();
                                sorted_keys.sort_by(|a, b| a.1.cmp(&b.1)); // Sorting by the 'name' (value)
                                for (password, name) in sorted_keys.iter() {
                                    debug!("Trying {} decryption key", name);

                                    if let Ok(decrypted_data) = aes_128_cbc_decrypt(
                                        cipher_data,
                                        password,
                                        MessageDigest::SHA256,
                                        Some(&iv),
                                    ) {
                                        // Decryption suceeded, check decrypted magic bytes
                                        if let Some(decrypted_magic) = decrypted_data
                                            .get(DECRYPTED_MAGIC_START..DECRYPTED_MAGIC_END)
                                        {
                                            if decrypted_magic == DECRYPTED_MAGIC {
                                                return Ok(decrypted_data);
                                            } else {
                                                warn!("Decrypted magic bytes do not match");
                                            }
                                        } else {
                                            warn!("Failed to read decrypted magic bytes");
                                        }
                                    } else {
                                        warn!("Decryption failed");
                                    }
                                }
                            } else {
                                debug!("Failed to read encrypted data");
                                return Err(DecryptError::Input);
                            }
                        }
                    }
                } else {
                    debug!("Failed to read IV from encrypted data");
                    return Err(DecryptError::Input);
                }
            } else {
                debug!("Failed to read encrypted data size");
                return Err(DecryptError::Input);
            }
        } else {
            debug!("Encrypted magic bytes do not match");
            return Err(DecryptError::Input);
        }
    } else {
        debug!("Failed to read encrypted header magic bytes");
        return Err(DecryptError::Input);
    }

    debug!("All decryption keys failed");
    Err(DecryptError::Decrypt)
}
