use std::io;
use core::panic;

use bip39::{Language, Mnemonic, MnemonicType};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use shamir_secret_sharing::num_bigint::{BigInt, Sign};

const PRIME_NUMBER: &[u8] = b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const SHARE_AMOUNT: usize = 3;
const THRESHOLD: usize = 2;


fn secret_sharing(seed_phrase: &Mnemonic) {
    println!("--- Secret Sharing ---\n");

    let sss = SSS {
        threshold: THRESHOLD,
        share_amount: SHARE_AMOUNT,
        prime: BigInt::parse_bytes(PRIME_NUMBER, 16).unwrap(),
    };

    let secret = BigInt::from_bytes_be(Sign::Plus, seed_phrase.entropy());

    let shares = sss.split(secret.clone());

    for (index, share) in shares.iter().enumerate() {
        clear_screen();
        let share_entropy = share.1.to_bytes_be().1;
        let share_mnemonic = Mnemonic::from_entropy(&share_entropy, Language::English).unwrap();
        println!("--- Share {} ---\n\n{}\n", index+1, share_mnemonic.phrase());

        key_enter();
    }
}

fn recover_wallet(shares: Vec<(usize, BigInt)>) {

    clear_screen();

    let sss = SSS {
        threshold: THRESHOLD,
        share_amount: SHARE_AMOUNT,
        prime: BigInt::parse_bytes(PRIME_NUMBER, 16).unwrap(),
    };

    let secret = sss.recover(&shares);

    let recovered_mnemonic = Mnemonic::from_entropy(&secret.to_bytes_be().1, Language::English).unwrap();
    println!(">>> Recovered mnemonic success!\n{}", recovered_mnemonic.phrase());

    key_enter();
}

fn create_wallet() {
    println!("--- Wallet Mnemonics ---\n");
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);

    for (index, word) in mnemonic.phrase().split_whitespace().enumerate() {
        println!("{:width$}. {}", index + 1, word, width = 2);
    }
}

fn input_mnemonic() -> Mnemonic {
    println!("Enter the seed phrase, each word separated by a space:\n");
    let mut mnemonic = String::new();

    io::stdin()
        .read_line(&mut mnemonic)
        .expect("Failed to read line");

    let seed_phrase = Mnemonic::from_phrase(&mnemonic, Language::English).unwrap();
    seed_phrase.clone()
}

fn clear_screen() {
    clearscreen::clear().expect("Failed to clear screen");
}

fn key_enter() {
    println!("\nPress enter to continue...");
    let mut _input = String::new();
    io::stdin()
        .read_line(&mut _input)
        .expect("Failed to read line");
}

fn main() {
    loop {
        clear_screen();

        // --- Main menu ---
        println!("
--- Wallet Manager ---

1. Create wallet
2. Secret sharing
3. Recover wallet

Select an option and press enter.
            ");
        
        let mut option = String::new();

        io::stdin()
            .read_line(&mut option)
            .expect("Failed to read line");

        let option: u32 = option.trim().parse().expect("Please type a number");
        clear_screen();

        match option {
            1 => {
                create_wallet();
                key_enter();
            }
            2 => {
                println!("--- Secret Sharing ---\n");
                let seed_phrase = input_mnemonic();
                secret_sharing(&seed_phrase);
            }
            3 => {
                let mut shares: Vec<(usize, BigInt)> = Vec::new();
                for _i in 0..THRESHOLD {
                    clear_screen();

                    println!("Enter share number (1-{}):", SHARE_AMOUNT);
                    let mut share_number = String::new();
                    io::stdin()
                        .read_line(&mut share_number)
                        .expect("Failed to read line");
                    let share_number: usize = share_number.trim().parse().expect("Please type a number");

                    // Check valid share number
                    if share_number > SHARE_AMOUNT || share_number < 1 {
                        panic!("Invalid share number");
                    }

                    println!("Enter mnemonics for share {}:", share_number);
                    let mut share = String::new();
                    io::stdin()
                        .read_line(&mut share)
                        .expect("Failed to read line");
                
                    let share_mnemonic = Mnemonic::from_phrase(&share, Language::English).unwrap();
                    let share_bigint = BigInt::from_bytes_be(Sign::Plus, share_mnemonic.entropy());
                    shares.push((share_number, share_bigint));
                }

                recover_wallet(shares);
            }
            _ => {
                panic!("Invalid option");
            }
        }
    }
}