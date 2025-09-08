use crate::reverse::rsa_encryption::encrypt_payload;

pub struct Compressor {
    charset: String,
}

impl Compressor {
    pub fn new(charset: String) -> Self {
        Self { charset }
    }

    pub fn compress(&self, input: &str) -> String {
        let rand_bytes = &mut rand::random::<[u8; 128]>();
        encrypt_payload(input, &self.charset, rand_bytes)
    }
}
