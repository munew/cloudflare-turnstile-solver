use base64::Engine;

pub struct CloudflareXorEncryption {
    key: Vec<u8>,
}

impl CloudflareXorEncryption {
    pub fn new(xor_key: &str, c_ray: &str) -> Self {
        let first = &c_ray[0..2];
        let second = &c_ray[2..];
        
        Self {
            key: Vec::from(format!("{first}{xor_key}{second}")),
        }
    }

    pub fn encrypt(&self, data: serde_json::Value) -> String {
        let serialized = serde_json::to_string(&data).unwrap();
        self.encrypt_raw(&serialized)
    }

    pub fn encrypt_raw(&self, raw: &str) -> String {
        let encrypted: Vec<u8> = raw
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(idx, chr)| chr ^ *self.key.get(idx % self.key.len()).unwrap())
            .collect();

        base64::prelude::BASE64_STANDARD.encode(&encrypted)
    }

    pub fn decrypt(&self, encrypted: &str) -> serde_json::Value {
        let encrypted = base64::prelude::BASE64_STANDARD.decode(encrypted).unwrap();

        let decrypted: Vec<u8> = encrypted
            .into_iter()
            .enumerate()
            .map(|(idx, chr)| chr ^ *self.key.get(idx % self.key.len()).unwrap())
            .collect();

        let serialized = String::from_utf8(decrypted).unwrap();
        serde_json::from_str(&serialized).unwrap()
    }
}

pub fn decrypt_cloudflare_response(ray: &str, data: &str) -> Result<String, anyhow::Error> {
    let key = format!("{ray}_0");

    let mut h: u8 = 32;
    for byte in key.bytes() {
        h ^= byte;
    }

    let raw = base64::prelude::BASE64_STANDARD.decode(data)?;

    let mut out_bytes: Vec<u8> = Vec::with_capacity(raw.len());
    for (i, &byte) in raw.iter().enumerate() {
        let byte_val = byte as i32;
        let h_val = h as i32;
        let i_mod_corrected = (i % 65535) as i32;

        let temp = byte_val - h_val - i_mod_corrected;
        let dec = ((temp % 255) + 255) % 255;
        out_bytes.push(dec as u8);
    }

    String::from_utf8(out_bytes).map_err(|e| e.into())
}
