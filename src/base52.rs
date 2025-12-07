use base64::DecodeError;

const BASE52_ALPHABET: &[u8; 52] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub struct Base52Codec;

impl Base52Codec {
    pub fn encode<T>(&self, input: T) -> String
    where
        T: AsRef<[u8]>,
        Self: Send + Sync,
    {
        let input = input.as_ref();

        // Count leading zeros
        let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

        // encode method
        if input.is_empty() {
            // encode empty input as empty string
            return "".to_string();
        }

        // Copy input to mutable vector (big integer in base 256)
        let mut num = input[leading_zeros..].to_vec();

        let mut encoded = Vec::new();

        while !num.is_empty() {
            let mut remainder = 0u32;
            let mut new_num = Vec::with_capacity(num.len());

            // Long division by 52 on big integer num
            for &byte in &num {
                let accumulator = (remainder << 8) + byte as u32;
                let digit = accumulator / 52;
                remainder = accumulator % 52;

                if !new_num.is_empty() || digit != 0 {
                    new_num.push(digit as u8);
                }
            }

            encoded.push(BASE52_ALPHABET[remainder as usize]);
            num = new_num;
        }

        encoded.reverse();

        // Prepend 'A' for each leading zero in input (zero digit in Base52 alphabet)
        let mut result = vec![b'A'; leading_zeros];
        result.extend(encoded);

        // If all input bytes were zero, encoded is empty and result will be only leading zeros.
        // If input is all zero bytes, result will be at least one 'A'.
        if result.is_empty() {
            result.push(b'A');
        }

        String::from_utf8(result).unwrap()
    }

    pub fn decode<T>(&self, input: T) -> Result<Vec<u8>, DecodeError>
    where
        T: AsRef<[u8]>,
        Self: Send + Sync,
    {
        let bytes = input.as_ref();

        // Count leading 'A's (zero digit)
        let leading_zeros = bytes.iter().take_while(|&&c| c == b'A').count();

        let mut num = Vec::new(); // big-endian big integer

        for &c in bytes.iter().skip(leading_zeros) {
            let value = match BASE52_ALPHABET.iter().position(|&x| x == c) {
                Some(i) => i as u32,
                None => return Err(DecodeError::InvalidByte(1, c)),
            };

            let mut carry = value;
            let mut new_num = Vec::with_capacity(num.len() + 1);

            // Multiply big-int by 52 and add carry
            for &digit in num.iter().rev() {
                let acc = digit as u32 * 52 + carry;
                new_num.push((acc & 0xFF) as u8);
                carry = acc >> 8;
            }

            while carry > 0 {
                new_num.push((carry & 0xFF) as u8);
                carry >>= 8;
            }

            // Convert little-endian → big-endian
            new_num.reverse();
            num = new_num;
        }

        // Prepend leading zero bytes
        let mut result = vec![0u8; leading_zeros];
        result.extend(num);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::Base52Codec;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_empty_input() {
        let codec = Base52Codec;
        let input: &[u8] = &[];
        let encoded = codec.encode(input);
        assert_eq!(encoded, ""); // empty input encoded as empty string ""
        let decoded = codec.decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, Vec::<u8>::new());
    }

    #[test]
    fn test_all_zero_input() {
        let codec = Base52Codec;
        let input = vec![0, 0, 0, 0];
        let encoded = codec.encode(&input);
        assert_eq!(encoded, "AAAA"); // 4 leading zeros => "AAAA"
        let decoded = codec.decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_single_byte_inputs() {
        let codec = Base52Codec;
        for b in 0u8..=255 {
            let input = [b];
            let encoded = codec.encode(input);
            let decoded = codec.decode(encoded.as_bytes()).unwrap();
            assert_eq!(decoded, input, "Failed for byte value: {b}");
        }
    }

    #[test]
    fn test_known_values() {
        let codec = Base52Codec;

        let input = b"Hello, Base52!";
        let encoded = codec.encode(input);
        let decoded = codec.decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_large_random_inputs() {
        let codec = Base52Codec;

        let mut rng = StdRng::seed_from_u64(42); // deterministic RNG for reproducibility

        for size in &[1usize, 10, 100, 1000, 5000] {
            let mut input = vec![0u8; *size];
            rng.fill_bytes(&mut input);
            let encoded = codec.encode(&input);
            let decoded = codec.decode(encoded.as_bytes()).unwrap();
            assert_eq!(decoded, input, "Failed for size: {size}");
        }
    }

    #[test]
    fn test_decode_invalid_characters() {
        let codec = Base52Codec;

        let invalid_inputs = ["Hello123", "Hello World!", "ABCD$%^", "abc\u{2603}def"];

        for &input in &invalid_inputs {
            let result = codec.decode(input.as_bytes());
            assert!(result.is_err(), "Invalid input '{input}' should error");
        }
    }

    #[test]
    fn test_round_trip_various_inputs() {
        let codec = Base52Codec;

        let test_cases: &[&[u8]] = &[
            b"",
            b"\0",
            b"\0\0\0",
            b"f",
            b"foobar",
            b"The quick brown fox jumps over the lazy dog",
            b"\xff\xfe\xfd\xfc\xfb",
        ];

        for &input in test_cases {
            let encoded = codec.encode(input);
            let decoded = codec.decode(encoded.as_bytes()).unwrap();

            if input.iter().all(|&b| b == 0) {
                assert_eq!(
                    decoded, input,
                    "Round-trip failed for all-zero input {input:?}"
                );
            } else {
                assert_eq!(decoded, input, "Round-trip failed for input {input:?}");
            }
        }
    }
}
