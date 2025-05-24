use aes::Aes256;
use cbc::{cipher::KeyIvInit, Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut};
use hex::{decode, encode};
use rand::RngCore;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{PathBuf},
};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn encrypt(file_path: &str) -> io::Result<String> {
    // Read the plaintext bytes
    let mut data = Vec::new();
    File::open(file_path)?.read_to_end(&mut data)?;

    // Generate a random key and IV
    let mut key = [0u8; 32];
    let mut iv  = [0u8; 16];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    println!("🔑 Key: {}", encode(key));
    println!("⚓ IV : {}", encode(iv));

    // Pad and encrypt
    let mut buf = data.clone();
    buf.resize(data.len() + 16, 0);
    let cipher = Aes256CbcEnc::new(&key.into(), &iv.into());
    let ct = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("padding error: {:?}", e)))?;

    // Write out IV || ciphertext
    let out_path = format!("{}.enc", file_path);
    let mut fout = File::create(&out_path)?;
    fout.write_all(&iv)?;
    fout.write_all(ct)?;

    // Delete the original
    fs::remove_file(file_path)?;

    Ok(out_path)
}

pub fn decrypt(enc_path: &str) -> io::Result<String> {
    // Read the encrypted file
    let mut all = Vec::new();
    File::open(enc_path)?.read_to_end(&mut all)?;

    // Split IV and ciphertext
    if all.len() < 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too short"));
    }
    let iv = &all[..16];
    let ct = &all[16..];

    // Prompt for the key
    println!("Paste the hex key for {}:", enc_path);
    let mut hex_key = String::new();
    io::stdin().read_line(&mut hex_key)?;
    let key_vec = decode(hex_key.trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex key"))?;
    if key_vec.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);

    // Decrypt
    let mut buf = ct.to_vec();
    let cipher = Aes256CbcDec::new(&key.into(), iv.into());
    let pt = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("padding error: {:?}", e)))?;

    // Compute output path by removing only the ".enc" extension
    let mut out_path = PathBuf::from(enc_path);
    if out_path.extension().and_then(|s| s.to_str()) == Some("enc") {
        out_path.set_extension(""); // remove ".enc"
        if let Some(filename) = out_path.file_name() {
            // PathBuf sets an empty extension, so we need to restore the dot in the name
            let name = filename.to_string_lossy();
            out_path.set_file_name(name.to_string());
        }
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected .enc extension"));
    }

    // Write decrypted bytes
    let mut fout = File::create(&out_path)?;
    fout.write_all(pt)?;

    // Delete the encrypted file
    fs::remove_file(enc_path)?;

    Ok(out_path.to_string_lossy().into_owned())
}
