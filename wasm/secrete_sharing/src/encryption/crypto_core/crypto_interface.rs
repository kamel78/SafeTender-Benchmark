use aes::{
    cipher::{generic_array::GenericArray},
};
use base64::{engine::general_purpose, Engine};
use hkdf::Hkdf;
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::Sha256;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};

use crate::{
    curves::curves_core::curve_arithmetics::{Point, Secp256k1},
    fields::fields_core::{
        arithmetic_interface::ArithmeticOperations, prime_fields::FieldElement,
    },
};
use web_sys::console;
use web_sys::window;


use crate::encryption::crypto_core::chacha::chacha_poly1305::ChaCha20Poly1305;

    fn now_ms() -> f64 {
        window()
            .unwrap()
            .performance()
            .unwrap()
            .now()
    }

    fn encrypt_chacha20_poly1305( plaintext: &str, key: u128) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key);
        let mut rng = OsRng;
        let nonce: [u8; 12] = rng.gen();
        let aad: [u8; 0] = [];
        let (ciphertext, tag) =
            cipher.encrypt(&nonce, plaintext.as_bytes(), &aad);
        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&ciphertext);
        combined
    }

    fn decrypt_chacha20_poly1305( data: &[u8], key: u128) -> Result<String, &'static str> {

        if data.len() < 28 { return Err("Invalid ciphertext");    }
        let cipher = ChaCha20Poly1305::new(key);
        let nonce: [u8; 12] = data[0..12]
            .try_into()
            .map_err(|_| "Invalid nonce")?;
        let tag: [u8; 16] = data[12..28]
            .try_into()
            .map_err(|_| "Invalid tag")?;
        let ciphertext = &data[28..];
        let aad: [u8; 0] = [];
        let plaintext =
            cipher.decrypt(&nonce, ciphertext, &aad, &tag)?;
        String::from_utf8(plaintext)
            .map_err(|_| "Invalid UTF-8")
    }

    fn encrypt_chacha20_poly1305_bytes( plaintext: &[u8],key: u128) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key);
        let mut rng = OsRng;
        let nonce: [u8; 12] = rng.gen();
        let aad: [u8; 0] = [];
        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, &aad);
        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&ciphertext);
        combined
    }

    fn decrypt_chacha20_poly1305_bytes( data: &[u8], key: u128) -> Result<Vec<u8>, &'static str> {
        if data.len() < 28 {        return Err("Invalid ciphertext");    }
        let cipher = ChaCha20Poly1305::new(key);
        let nonce: [u8; 12] = data[0..12]
            .try_into()
            .map_err(|_| "Invalid nonce")?;
        let tag: [u8; 16] = data[12..28]
            .try_into()
            .map_err(|_| "Invalid tag")?;
        let ciphertext = &data[28..];
        let aad: [u8; 0] = [];
        cipher.decrypt(&nonce, ciphertext, &aad, &tag)
    }


    pub fn decode_base64_jwt_key(jwt_key: &str) -> Vec<u8> {
        let jwt_key = jwt_key.trim();
        let jwt_key = jwt_key.replace(&[' ', '\n', '\r'][..], "");
        if let Ok(decoded) = general_purpose::STANDARD.decode(&jwt_key) {
            return decoded;
        }
        if let Ok(decoded) = general_purpose::URL_SAFE.decode(&jwt_key) {
            return decoded;
        }
        if let Ok(decoded) = general_purpose::STANDARD_NO_PAD.decode(&jwt_key) {
            return decoded;
        }
        if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(jwt_key) {
            return decoded;
        }
        panic!("Failed to decode base64 JWT key after trying all variants");
    }

    pub fn encode_base64_jwt_key(key: &[u8]) -> String {
            general_purpose::URL_SAFE_NO_PAD.encode(key)
    }

#[derive(Clone, Debug)]
pub struct LightEciCrypt<'a, const R: usize, const N: usize> {
    curve: &'a Secp256k1<'static, R, N>,
}

impl<'a, const R: usize, const N: usize> LightEciCrypt<'a, R, N> {
    
    pub fn new(curve: &'a Secp256k1<'static, R, N>) -> Self {
        LightEciCrypt { curve }
    }

    pub fn encrypt_string(&self, input: &str, public_key: &Point<'a, R, N>) -> String {
        if (!std::ptr::eq(self.curve, public_key.curve)) || (!public_key.is_on_curve()) {
            panic!("Public key is not on the correct targeted curve.");
        }
        if public_key.is_infinity() {
            panic!("Invalid public key.");
        }
        let r_key = self.curve.fr.random_element();
        let p_key = public_key.multiply(&r_key);
        let t_key = self
            .curve
            .generator()
            .multiply(&r_key)
            .derive_hkdf(128, None);
        let t_key_bytes: [u8; 16] = t_key
            .as_slice()
            .try_into()
            .expect("Derived HKDF key must be 16 bytes");
        let mut combined = p_key.to_compressed_bytearray();
        combined.extend(encrypt_chacha20_poly1305(input, u128::from_le_bytes(t_key_bytes)));
        general_purpose::STANDARD.encode(&combined)
    }

    pub fn decrypt_string(&self, input: &str, secret_key: &FieldElement<R>) -> String {
        let raw_message = general_purpose::STANDARD.decode(input).unwrap();
        let size_in_bytes = self.curve.generator().to_compressed_bytearray().len();
        let (key_part, aes_part) = raw_message.split_at(size_in_bytes);
        let t_key = self
            .curve
            .from_bytearray(&key_part.to_vec())
            .multiply(&secret_key.invert());
        let t_key = t_key.derive_hkdf(128, None);
        let t_key_bytes: [u8; 16] = t_key
            .as_slice()
            .try_into()
            .expect("Derived HKDF key must be 16 bytes");
        decrypt_chacha20_poly1305(aes_part, u128::from_le_bytes(t_key_bytes)).unwrap()
    }
       
    pub fn generate_key_pair(&self) -> (String, String) {
        let private_key = self.curve.fr.random_element();
        let public_key = self.curve.generator().multiply(&private_key);       
        let private_key_b64 = private_key.to_base64();
        let public_key_b64 = public_key.to_base64();
        (private_key_b64, public_key_b64)
    }
    
   
   pub fn encrypt_private_key_with_export_key(&self, private_key: &str, export_key: &[u8]) -> String {
        if export_key.is_empty() {        panic!("Export key is empty");    }
        let salt = self.generate_salt();
        let encryption_key = self.derive_key_with_salt_bytes(export_key, &salt);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
        let nonce_bytes: [u8; 12] = OsRng.gen(); 
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, private_key.as_bytes())
            .expect("encryption failure!");
        let mut combined = Vec::new();
        combined.extend(&salt);        // 16 bytes
        combined.extend(&nonce_bytes); // 12 bytes
        combined.extend(encrypted);    // ciphertext + tag
        general_purpose::STANDARD.encode(&combined)
    }

    pub fn decrypt_private_key_with_export_key( &self, encrypted_key: &str,  export_key: &[u8]) -> String {
        if export_key.is_empty() {    panic!("Export key is empty");    }
        let decoded = general_purpose::STANDARD
            .decode(encrypted_key)
            .expect("Failed to decode encrypted key");
        let salt = &decoded[..16];
        let nonce = &decoded[16..28];
        let ciphertext = &decoded[28..];
        let encryption_key = self.derive_key_with_salt_bytes(export_key, salt);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
        let nonce = Nonce::from_slice(nonce);
        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .expect("decryption failure: wrong export key or corrupted data");
        String::from_utf8(decrypted).expect("Decrypted data is not valid UTF-8")
    }
        pub fn encrypt_with_public_key(&self, plaintext: &str, public_key_b64: &str) -> String {
        self.encrypt_string_base64key(plaintext, public_key_b64)
    }

    pub fn decrypt_with_private_key(&self, ciphertext: &str, private_key_b64: &str) -> String {
        self.decrypt_string_base64key(ciphertext, private_key_b64)
    }
    
    fn generate_salt(&self) -> Vec<u8> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt.to_vec()
    }

    fn derive_key_with_salt_bytes(&self, input: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut encryption_key = [0u8; 16];
        Hkdf::<Sha256>::new(Some(salt), input)
            .expand(b"private_key_encryption", &mut encryption_key)
            .expect("HKDF expansion failed");
        encryption_key.to_vec()
    }
    
    pub fn encrypt_with_export_key(&self, plaintext: &str, export_key: &[u8]) -> String {
        if export_key.is_empty() { panic!("Export key cannot be empty");}
        let salt = self.generate_salt();
        let nonce_bytes: [u8; 12] = OsRng.gen();
        let encryption_key = self.derive_key_with_salt_bytes(export_key, &salt);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("Encryption failure");
        let mut combined = Vec::new();
        combined.extend(&salt);
        combined.extend(&nonce_bytes);
        combined.extend(encrypted);
        general_purpose::STANDARD.encode(&combined)
    }

    pub fn decrypt_with_export_key(&self, ciphertext: &str, export_key: &[u8]) -> String {
        if export_key.is_empty() {  panic!("Export key cannot be empty");}
        let decoded = general_purpose::STANDARD
            .decode(ciphertext)
            .expect("Failed to decode ciphertext");
        let salt = &decoded[..16];
        let nonce = &decoded[16..28];
        let ciphertext_with_tag = &decoded[28..];
        let encryption_key = self.derive_key_with_salt_bytes(export_key, salt);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
        let nonce = Nonce::from_slice(nonce);
        let decrypted = cipher
            .decrypt(nonce, ciphertext_with_tag)
            .expect("Decryption failure - wrong key or corrupted data");
        String::from_utf8(decrypted).expect("Decrypted data is not valid UTF-8")
    }

    pub fn decrypt_string_base64key(&self, input: &str, secret_key: &str) -> String {
        self.decrypt_string(input, &self.curve.fr.from_base64(secret_key))
    }

    pub fn encrypt_string_base64key(&self, input: &str, public_key: &str) -> String {
        self.encrypt_string(input, &self.curve.from_base64(public_key))
    }

    pub fn encrypt_pdf_bytes( &self, input_bytes: &[u8], public_key_str: &str) -> (Vec<u8>, f64)
    {
        
        let public_key = self.curve.from_base64(public_key_str);
        if (!std::ptr::eq(self.curve, public_key.curve)) || (!public_key.is_on_curve()) {
                console::log_1(&"Public key is not on the correct targeted curve.".into());
                panic!("Public key is not on the correct targeted curve.");
        }
        if public_key.is_infinity() {
                    console::log_1(&"Invalid public key.".into());
                    panic!("Invalid public key.");
                }
        let start =  now_ms();
        let r_key = self.curve.fr.random_element();
        let p_key = public_key.multiply(&r_key);
        let t_key = self
            .curve
            .generator()
            .multiply(&r_key)
            .derive_hkdf(128, None);
        let mut combined = p_key.to_compressed_bytearray();
        let t_key_bytes: [u8; 16] = t_key
            .as_slice()
            .try_into()
            .expect("Derived HKDF key must be 16 bytes");
        combined.extend(encrypt_chacha20_poly1305_bytes(
            input_bytes,
            u128::from_le_bytes(t_key_bytes),
        ));
        let elapsed_ms =  now_ms() - start ;
        (combined, elapsed_ms)
    }

    pub fn decrypt_pdf_bytes( &self, raw_message: &[u8], secret_key_str: &str) -> (Vec<u8>, f64)
    {
        let start =  now_ms();
        let secret_key = self.curve.fr.from_base64(&secret_key_str);
        let size_in_bytes = self
            .curve
            .generator()
            .to_compressed_bytearray()
            .len();
        let (key_part, aes_part) = raw_message.split_at(size_in_bytes);
        let t_key = self
            .curve
            .from_bytearray(&key_part.to_vec())
            .multiply(&secret_key.invert())
            .derive_hkdf(128, None);
        let t_key_bytes: [u8; 16] = t_key
            .as_slice()
            .try_into()
            .expect("Derived HKDF key must be 16 bytes");
        let output = decrypt_chacha20_poly1305_bytes(
            aes_part,
            u128::from_le_bytes(t_key_bytes),
        )
        .unwrap();
        let time_ms =  now_ms() - start ;
        (output, time_ms)
    }

}