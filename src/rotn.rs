pub fn rot_n_encode(input: &str, shift: u8) -> String {
    let s = shift % 26;
    input
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                ((((c as u8 - b'a') + s) % 26) + b'a') as char
            } else if c.is_ascii_uppercase() {
                ((((c as u8 - b'A') + s) % 26) + b'A') as char
            } else {
                c
            }
        })
        .collect()
}

pub fn rot_n_decode(input: &str, shift: u8) -> String {
    let rev = (26 - (shift % 26)) % 26;

    input
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                ((((c as u8 - b'a') + rev) % 26) + b'a') as char
            } else if c.is_ascii_uppercase() {
                ((((c as u8 - b'A') + rev) % 26) + b'A') as char
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{rot_n_decode, rot_n_encode};

    #[test]
    fn basic_encoding_decoding() {
        assert_eq!(rot_n_encode("abc", 1), "bcd");
        assert_eq!(rot_n_encode("ABC", 1), "BCD");
        assert_eq!(rot_n_decode("bcd", 1), "abc");
        assert_eq!(rot_n_decode("BCD", 1), "ABC");
    }

    #[test]
    fn wrap_around() {
        assert_eq!(rot_n_encode("xyz", 3), "abc");
        assert_eq!(rot_n_encode("XYZ", 3), "ABC");
        assert_eq!(rot_n_decode("abc", 3), "xyz");
        assert_eq!(rot_n_decode("ABC", 3), "XYZ");
    }

    #[test]
    fn shift_zero_and_full_cycle() {
        let s = "Hello, World!";
        assert_eq!(rot_n_encode(s, 0), s);
        assert_eq!(rot_n_encode(s, 26), s);
        assert_eq!(rot_n_decode(s, 26), s);
    }

    #[test]
    fn large_shift_modulo_behavior() {
        // shift 27 == shift 1
        assert_eq!(rot_n_encode("aZ", 27), rot_n_encode("aZ", 1));
        // shift 255 -> 255 % 26 == 21, verify roundtrip for that effective shift
        let eff = 255u8 % 26;
        let enc = rot_n_encode("Rust", 255);
        assert_eq!(rot_n_decode(&enc, 255), "Rust");
        assert_eq!(rot_n_encode("Rust", eff), enc);
    }

    #[test]
    fn preserve_non_letters_and_empty() {
        let s = "1234 !@# 😊 åßç";
        assert_eq!(rot_n_encode(s, 5), s);
        assert_eq!(rot_n_decode(s, 5), s);
        assert_eq!(rot_n_encode("", 10), "");
        assert_eq!(rot_n_decode("", 10), "");
    }

    #[test]
    fn roundtrip_for_alphabets_many_shifts() {
        let shifts = [0u8, 1, 5, 13, 25];
        for &sh in &shifts {
            // lowercase
            let alpha = "abcdefghijklmnopqrstuvwxyz";
            let enc = rot_n_encode(alpha, sh);
            assert_eq!(
                rot_n_decode(&enc, sh),
                alpha,
                "lowercase failed for shift {}",
                sh
            );
            // uppercase
            let alpha_u = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let enc_u = rot_n_encode(alpha_u, sh);
            assert_eq!(
                rot_n_decode(&enc_u, sh),
                alpha_u,
                "uppercase failed for shift {}",
                sh
            );
        }
    }
}
