mod encryptor { pub mod encryptor; }
use encryptor::encryptor::{encrypt, decrypt};

fn main() {
    // Encrypt the pdf
    match encrypt("files/file-example.pdf") {
        Ok(enc) => println!("Encrypted → {}", enc),
        Err(e) => eprintln!("Encrypt error: {}", e),
    }

    // Decrypt it
    match decrypt("files/file-example.pdf.enc") {
        Ok(orig) => println!("Decrypted → {}", orig),
        Err(e) => eprintln!("Decrypt error: {}", e),
    }
}
