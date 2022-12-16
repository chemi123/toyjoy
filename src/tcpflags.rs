pub const CWR: u8 = 1 << 7;
pub const ECE: u8 = 1 << 6;
pub const URG: u8 = 1 << 5;
pub const ACK: u8 = 1 << 4;
pub const PSH: u8 = 1 << 3;
pub const RST: u8 = 1 << 2;
pub const SYN: u8 = 1 << 1;
pub const FIN: u8 = 1;

pub fn get_bit_mask(flag: u8) -> u8 {
    let mask = CWR | ECE | URG | ACK | PSH | RST | SYN | FIN;
    mask ^ flag
}

pub fn flag_to_string(flag: u8) -> String {
    let mut flag_str = String::new();
    flag_str.reserve(50);

    if flag & SYN > 0 {
        flag_str.push_str("SYN ");
    }
    if flag & FIN > 0 {
        flag_str.push_str("FIN ");
    }
    if flag & RST > 0 {
        flag_str.push_str("RST ");
    }
    if flag & CWR > 0 {
        flag_str.push_str("CWR ");
    }
    if flag & ECE > 0 {
        flag_str.push_str("ECE ");
    }
    if flag & PSH > 0 {
        flag_str.push_str("PSH ");
    }
    if flag & URG > 0 {
        flag_str.push_str("URG");
    }
    flag_str
}
