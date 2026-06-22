pub struct ChaCha20Poly1305 {
    key: [u32; 8],
}

impl ChaCha20Poly1305 {
    pub fn new(key: u128) -> Self {
        // Convert u128 key to 8 u32 words (256-bit key)
        let key_bytes = key.to_le_bytes();
        let mut key_words = [0u32; 8];
        
        // First half: direct conversion
        for i in 0..4 {
            key_words[i] = u32::from_le_bytes([
                key_bytes[i * 4],
                key_bytes[i * 4 + 1],
                key_bytes[i * 4 + 2],
                key_bytes[i * 4 + 3],
            ]);
        }
        
        // Second half: repeat the key
        for i in 0..4 {
            key_words[i + 4] = key_words[i];
        }
        
        Self { key: key_words }
    }
    
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
    }
    
    fn chacha20_block(&self, nonce: &[u8; 12], counter: u32) -> [u8; 64] {
        // ChaCha20 constants "expand 32-byte k"
        let mut state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            self.key[0], self.key[1], self.key[2], self.key[3],
            self.key[4], self.key[5], self.key[6], self.key[7],
            counter,
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];
        
        let initial_state = state;
        
        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut state, 0, 4, 8, 12);
            Self::quarter_round(&mut state, 1, 5, 9, 13);
            Self::quarter_round(&mut state, 2, 6, 10, 14);
            Self::quarter_round(&mut state, 3, 7, 11, 15);
            
            // Diagonal rounds
            Self::quarter_round(&mut state, 0, 5, 10, 15);
            Self::quarter_round(&mut state, 1, 6, 11, 12);
            Self::quarter_round(&mut state, 2, 7, 8, 13);
            Self::quarter_round(&mut state, 3, 4, 9, 14);
        }
        
        // Add initial state
        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial_state[i]);
        }
        
        // Convert to bytes
        let mut output = [0u8; 64];
        for i in 0..16 {
            let bytes = state[i].to_le_bytes();
            output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        
        output
    }
    
    fn chacha20_encrypt(&self, nonce: &[u8; 12], counter: u32, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut current_counter = counter;
        
        for chunk in plaintext.chunks(64) {
            let keystream = self.chacha20_block(nonce, current_counter);
            
            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
            
            current_counter += 1;
        }
        
        ciphertext
    }
    
    // Poly1305 implementation
    fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        // Clamp r
        let mut r = [0u32; 5];
        r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff;
        r[1] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]) & 0x0ffffffc;
        r[2] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]) & 0x0ffffffc;
        r[3] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) & 0x0ffffffc;
        r[4] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]) & 0x0ffffffc;
        
        // Load s
        let s = [
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];
        
        let mut accumulator = [0u32; 5];
        
        // Process message in 16-byte chunks
        for chunk in message.chunks(16) {
            // Convert chunk to limbs (little-endian)
            let mut n = [0u32; 5];
            let len = chunk.len();
            
            for i in 0..len {
                n[i / 4] |= (chunk[i] as u32) << ((i % 4) * 8);
            }
            
            // Add padding bit
            n[len / 4] |= 1u32 << ((len % 4) * 8);
            
            // Add to accumulator
            let mut carry = 0u64;
            for i in 0..5 {
                carry += accumulator[i] as u64 + n[i] as u64;
                accumulator[i] = carry as u32;
                carry >>= 32;
            }
            
            // Multiply by r and reduce mod 2^130-5
            Self::poly1305_multiply(&mut accumulator, &r);
        }
        
        // Final reduction and add s
        Self::poly1305_freeze(&mut accumulator);
        
        let mut result = [0u8; 16];
        
        // Add s to accumulator
        let mut carry = 0u64;
        for i in 0..3 {
            carry += accumulator[i] as u64 + s[i] as u64;
            result[i * 4..(i + 1) * 4].copy_from_slice(&(carry as u32).to_le_bytes());
            carry >>= 32;
        }
        
        // Handle final limbs
        carry += accumulator[3] as u64;
        result[12..16].copy_from_slice(&(carry as u32).to_le_bytes());
        
        result
    }
    
    fn poly1305_multiply(h: &mut [u32; 5], r: &[u32; 5]) {
    let mut product = [0u64; 9];
    
    // Multiply
    for i in 0..5 {
        for j in 0..5 {
            product[i + j] += (h[i] as u64) * (r[j] as u64);
        }
    }
    
    // Reduce mod 2^130-5
    let mask = 0xffffffffu64;
    
    // Propagate carries
    for i in 0..8 {
        product[i + 1] += product[i] >> 32;
        product[i] &= mask;
    }
    
    // Reduce high bits
    let mut carry = product[5] >> 2;
    product[5] &= 3;
    
    carry += (product[6] << 30) + (product[7] << 62);
    product[6] = (product[6] >> 2) & mask;
    product[7] = (product[7] >> 2) & mask;
    product[8] = (product[8] >> 2) & mask;
    
    let c = carry + (product[8] << 30);
    carry = c * 5;
    
    // Add back reduced value
    for i in 0..5 {
        carry += product[i];
        h[i] = carry as u32;
        carry >>= 32;
    }
    
    // Final reduction - FIX HERE
    let mut c2 = (h[4] >> 2) as u64;  // Cast to u64
    h[4] &= 3;
    c2 = c2 * 5 + (carry as u64);  // Use u64 for arithmetic
    
    for i in 0..5 {
        c2 = c2 + h[i] as u64;  // Cast h[i] to u64
        h[i] = c2 as u32;       // Store lower 32 bits
        c2 = c2 >> 32;          // Now safe to shift
    }
}
    
    fn poly1305_freeze(h: &mut [u32; 5]) {
        // Compute h - (2^130 - 5)
        let mut g = [0u32; 5];
        let mut carry = 5u32;
        
        for i in 0..5 {
            carry = h[i].wrapping_add(carry);
            g[i] = carry;
            carry = if carry < h[i] || (i == 4 && carry >= h[i]) { 1 } else { 0 };
        }
        
        // If g >= 2^130, keep h; otherwise use g
        let mask = (g[4] >> 2).wrapping_sub(1);
        
        for i in 0..5 {
            h[i] = (h[i] & mask) | (g[i] & !mask);
        }
        
        // Final carry propagation
        let mut c = 0u64;
        for i in 0..4 {
            c += h[i] as u64;
            h[i] = c as u32;
            c >>= 32;
        }
        h[4] = (c + h[4] as u64) as u32;
    }
    
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Generate Poly1305 key using first block
        let poly_key_block = self.chacha20_block(nonce, 0);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_key_block[..32]);
        
        // Encrypt plaintext starting from counter 1
        let ciphertext = self.chacha20_encrypt(nonce, 1, plaintext);
        
        // Construct Poly1305 input: AAD || pad || ciphertext || pad || lengths
        let mut mac_data = Vec::new();
        
        // Add AAD
        mac_data.extend_from_slice(aad);
        
        // Pad AAD to 16 bytes
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        mac_data.resize(mac_data.len() + aad_pad, 0);
        
        // Add ciphertext
        mac_data.extend_from_slice(&ciphertext);
        
        // Pad ciphertext to 16 bytes
        let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
        mac_data.resize(mac_data.len() + ct_pad, 0);
        
        // Add lengths (little-endian)
        mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        
        // Compute MAC
        let tag = Self::poly1305_mac(&poly_key, &mac_data);
        
        (ciphertext, tag.to_vec())
    }
    
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        // Generate Poly1305 key using first block
        let poly_key_block = self.chacha20_block(nonce, 0);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_key_block[..32]);
        
        // Construct Poly1305 input
        let mut mac_data = Vec::new();
        
        // Add AAD
        mac_data.extend_from_slice(aad);
        
        // Pad AAD to 16 bytes
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        mac_data.resize(mac_data.len() + aad_pad, 0);
        
        // Add ciphertext
        mac_data.extend_from_slice(ciphertext);
        
        // Pad ciphertext to 16 bytes
        let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
        mac_data.resize(mac_data.len() + ct_pad, 0);
        
        // Add lengths
        mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        
        // Compute and verify MAC
        let computed_tag = Self::poly1305_mac(&poly_key, &mac_data);
        
        // Constant-time comparison
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= computed_tag[i] ^ tag[i];
        }
        
        if diff != 0 {
            return Err("Authentication failed");
        }
        
        // Decrypt ciphertext starting from counter 1
        let plaintext = self.chacha20_encrypt(nonce, 1, ciphertext);
        
        Ok(plaintext)
    }
}