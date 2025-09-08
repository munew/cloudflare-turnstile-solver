use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use std::{io::{Cursor, Read, Result, Write}, num::Wrapping};

/// Struct containing the `XTEA` info.
///
/// See <https://en.wikipedia.org/wiki/XTEA> for more information
///
#[derive(Debug)]
pub struct XTEA {
    key: [Wrapping<u32>; 4],
    num_rounds: Wrapping<u32>,
}

/// Reccomended default number of rounds
const DEFAULT_ROUNDS: u32 = 32;

/// Magic number specified by the algorithm
const DELTA: Wrapping<u32> = Wrapping(0x9E3779B9);

impl XTEA {
    /// Creates a new `XTEA` cipher using the given key.
    #[inline]
    pub fn new(key: &[u32; 4]) -> Self {
        Self::new_with_rounds(key, DEFAULT_ROUNDS)
    }

    /// Creates a new XTEA cipher using the given key, with a custom number of rounds.
    ///
    /// **HIGHLY Recommended** to use the fn `new(key: [u32; 4]) -> Self` instead unless you know what you're doing.
    ///
    /// # Panics
    ///
    /// If num_rounds is NOT divisible by 2.
    #[inline]
    pub fn new_with_rounds(key: &[u32; 4], num_rounds: u32) -> Self {
        assert_eq!(num_rounds & 1, 0, "num_rounds was not divisible by 2.");
        let key = [Wrapping(key[0]), Wrapping(key[1]), Wrapping(key[2]), Wrapping(key[3])];
        let num_rounds = Wrapping(num_rounds);
        XTEA {
            key,
            num_rounds,
        }
    }

    /// Enciphers the two given `u32`'s into the output array.
    ///
    /// Highly recommended to NOT use this, and instead use either the slice or stream implementation.
    ///
    /// See <https://en.wikipedia.org/wiki/XTEA#Implementations> for implementation details
    #[inline]
    pub fn encipher(&self, input: &[u32; 2], output: &mut [u32; 2]) {
        let mut v0 = Wrapping(input[0]);
        let mut v1 = Wrapping(input[1]);
        let mut sum = Wrapping(0u32);

        for _ in 0..self.num_rounds.0 as u32 {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + self.key[(sum.0 & 3) as usize]);
            sum += DELTA;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + self.key[((sum.0 >> 11) & 3) as usize]);
        }

        output[0] = v0.0;
        output[1] = v1.0;
    }

    /// Deciphers the two given `u32`'s into the output array.
    ///
    /// Highly recommended to NOT use this, and instead use either the slice or stream implementation.
    ///
    /// See <https://en.wikipedia.org/wiki/XTEA#Implementations> for implementation details
    #[inline]
    pub fn decipher(&self, input: &[u32; 2], output: &mut [u32; 2]) {
        let mut v0 = Wrapping(input[0]);
        let mut v1 = Wrapping(input[1]);
        let mut sum = DELTA * self.num_rounds;

        for _ in 0..self.num_rounds.0 as u32 {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + self.key[((sum.0 >> 11) & 3) as usize]);
            sum -= DELTA;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + self.key[(sum.0 & 3) as usize]);
        }

        output[0] = v0.0;
        output[1] = v1.0;
    }

    #[inline]
    pub fn encipher_u8slice<B: ByteOrder>(&self, input: &[u8], output: &mut [u8]) {
        self.cipher_u8slice::<B>(input, output, true)
    }


    #[inline]
    fn cipher_u8slice<B: ByteOrder>(&self, input: &[u8], output: &mut [u8], encipher: bool) {
        assert_eq!(input.len(), output.len(), "The input and output slices must be of the same length.");
        assert_eq!(input.len() % 8, 0, "Input and output slices must be of a length divisible by 8.");

        //Create cursors for the two slices, and pass it off to the stream cipher handler
        let mut input_reader = Cursor::new(input);
        let mut ouput_writer = Cursor::new(output);

        self.cipher_stream::<B, Cursor<&[u8]>, Cursor<&mut [u8]>>(&mut input_reader, &mut ouput_writer, encipher).unwrap()
        /*
        let mut input_buf = [0 as u32; 2];
        let mut output_buf = [0 as u32; 2];

        for _ in 0..iterations {
            input_buf[0] = input_reader.read_u32::<T>().unwrap();
            input_buf[1] = input_reader.read_u32::<T>().unwrap();

            if encipher {
                self.encipher(&input_buf, &mut output_buf);
            } else {
                self.decipher(&input_buf, &mut output_buf);
            }

            ouput_writer.write_u32::<T>(output_buf[0]).unwrap();
            ouput_writer.write_u32::<T>(output_buf[1]).unwrap();
        }
        */
    }

    #[inline]
    fn cipher_stream<B: ByteOrder, T: Read, S: Write>(&self, input: &mut T, output: &mut S, encipher: bool) -> Result<()> {
        let mut input_buf = [0 as u32; 2];
        let mut output_buf = [0 as u32; 2];

        loop {

            //An error parsing the first value means we should stop parsing, not fail
            input_buf[0] = match input.read_u32::<B>() {
                Ok(val) => val,
                Err(_) => break
            };
            input_buf[1] = input.read_u32::<B>()?;

            if encipher {
                self.encipher(&input_buf, &mut output_buf);
            } else {
                self.decipher(&input_buf, &mut output_buf);
            }

            output.write_u32::<B>(output_buf[0])?;
            output.write_u32::<B>(output_buf[1])?;
        }
        Ok(())
    }
}
