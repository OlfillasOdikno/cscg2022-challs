
type Word = [u8; 8];

const ROUNDS: usize = 32;

fn xorshift64(x64: &Word) -> Word {
    let mut next = u64::from_le_bytes(*x64);
    next ^= next << 13;
    next ^= next >> 7;
    next ^= next << 17;
    u64::to_be_bytes(next)
}

fn encrypt(text: &Word, key: &Word, sbox: &[u8; 256]) -> Word {
    let mut t = text[0];
    let mut text = text.clone();
    for i in 0..ROUNDS * 8 {
        t = t.wrapping_add(key[i & 0b111]);
        t = sbox[t as usize];
        t = t.wrapping_add(text[(i + 1) & 0b111]);
        t = t.rotate_left(1);
        text[(i + 1) & 0b111] = t;
    }
    text
}

fn encrypt_x(text: &Word, key: &Word, sbox: &[u8; 256], key_start: u8) -> Option<u8> {
    let mut t = text[0];
    let mut text = text.clone();
    let mut res = 0;
    for i in 0..ROUNDS * 8 {
        t = t.wrapping_add(key[i & 0b111]);
        res = t;
        if i != ROUNDS * 8 - 1 && !(t < key_start || t >= key_start + 8) {
            return None;
        }
        t = sbox[t as usize];
        t = t.wrapping_add(text[(i + 1) & 0b111]);
        t = t.rotate_left(1);
        text[(i + 1) & 0b111] = t;
    }
    Some(res)
}

fn xor(a: Word, b: Word) -> Word {
    (u64::from_le_bytes(a) ^ u64::from_le_bytes(b)).to_le_bytes()
}

fn main2_at(index: usize, sbox: &[u8; 256], prefix: &Vec<u8>, last: &Word, key_start: u8) {
    println!("{} bruting last", index);
    let mut rng = u64::to_le_bytes(88172645463325252);
    let mut full = Vec::new();
    full.extend(prefix);
    // last thing
    let memeidx = key_start + index as u8;

    'brute: loop {
        rng = xorshift64(&rng);

        let res = match encrypt_x(&last, &rng, &sbox, key_start) {
            Some(x) => x,
            None => continue 'brute,
        };

        if res != memeidx {
            continue 'brute;
        }
        full.extend(rng);
        break;
    }
    println!("{} done", index);
    std::fs::write(format!("res/{}.bin", index), full).unwrap();
}

fn main1() {
    std::fs::create_dir_all("res").unwrap();

    let mut last = [0u8; 8];
    let mut sbox = [0u8; 256];
    let mut rng = u64::to_le_bytes(88172645463325252);
    let bootloader = include_bytes!("../../pwn/dumped_bootloader");
    sbox.copy_from_slice(&bootloader[..256]);
    let key = [0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00];
    let key_start = bootloader.windows(8).position(|x| x == key).unwrap() as u8;

    let mut prefix = Vec::new();
    println!("bruting prefix");
    for _i in 0..63 {
        loop {
            rng = xorshift64(&rng);

            let res = match encrypt_x(&last, &rng, &sbox, key_start) {
                Some(x) => x,
                None => continue,
            };
            if res < key_start || res >= key_start + 8 {
                break;
            }
        }

        let res = encrypt(&last, &rng, &sbox);
        last = xor(res, last);
        prefix.extend(rng);
    }
    
    for i in 0..8 {
        main2_at(i, &sbox, &prefix, &last, key_start);
    }
    
}



fn main() {
    let bootloader = include_bytes!("../bootloader");
    let mut sbox = [0u8; 256];
    sbox.copy_from_slice(&bootloader[..256]);
    let expected = 0xd64d00928affd601u64.to_be_bytes();
    let key = [0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00];
    assert_eq!(encrypt(&[0x43; 8], &key, &sbox), expected);
    
    main1();
}
