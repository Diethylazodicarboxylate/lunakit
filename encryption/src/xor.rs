//! Payload Encryption -XOR
//! XOR encryption is the simplest to use and lightest to implement, which makes it a popular choice for malwares.
//! It is faster than most methods since its a simple CPU operation and needs no libs like AES or RC4 do.
//! Additionally, it is a bidirectional algorithm, so we have same way to encrypt and decrypt.
//! This does mean that if someone recognises its XOR, then they can pass the encrypted payload right back
//! to the routine to get it back as decrypted when reversing.

/// This code snippet below shows a basic encryption function which xors each byte of the shellcode
/// with a 1 byte key.
pub fn naieve_xor_by_one_key(shellcode: &mut [u8], key: u8) -> &[u8] {
    for i in 0..shellcode.len() {
        shellcode[i] = shellcode[i] ^ key
    }
    shellcode
}

/// There are better ways of securing the encryption key though.
/// Some tools and security solutions can brute the key which will expose the shellcode.
/// Since u8 has a very small space for guesswork, so brute methods are easy.
/// To make the guesswork harder, we can have some minor changes, like using the position
/// of the shellcode's byte, added to the key so we cannot simply bruteforce it and keyspace is larger.
pub fn xor_by_ikeys(shellcode: &mut [u8], key: u8) -> &[u8] {
    for i in 0..shellcode.len() {
        shellcode[i] = shellcode[i] ^ (key + i as u8)
    }
    shellcode
}

/// This would be a further hardened version. We perform the same encryption process with a single key
/// but we iterate through bytes of key as well, so we have a larger key-space for encryption.
/// This way there isn't a single byte of key to brute but "bytes in key" number of keys to bruteforce.
pub fn xor_by_inputkeys<'a>(shellcode: &'a mut [u8], key: &[u8]) -> &'a [u8] {
    let mut keyposition = 0;
    for i in 0..shellcode.len() {
        if keyposition >= key.len() {
            keyposition = 0;
        }
        shellcode[i] = shellcode[i] ^ key[keyposition];
        keyposition += 1;
    }

    shellcode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_naieve_xor_by_one_key_does() {
        let mut input = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = 123;
        let expected_out = [122, 121, 120, 127, 126, 125, 124, 115];
        let out = naieve_xor_by_one_key(&mut input[..], key);
        assert_eq!(expected_out, out);
    }

    #[test]
    fn test_xor_by_ikeys() {
        let mut input = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = 123;
        let expected_out = [122, 126, 126, 122, 122, 134, 134, 138];
        let out = xor_by_ikeys(&mut input[..], key);
        assert_eq!(expected_out, out);
    }

    #[test]
    pub fn test_xor_by_inputkeys() {
        let mut input = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = [10, 20, 30, 40, 50, 60, 70];
        let expected_out = [11, 22, 29, 44, 55, 58, 65, 2];
        let out = xor_by_inputkeys(&mut input[..], &key[..]);
        assert_eq!(expected_out, out);
    }
}
