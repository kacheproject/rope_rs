use rand;
use chrono::{Utc};

const EPOCH_START: u64 = 1400000000;

pub type KacheSimpleId = u64;

pub type KacheLongId = u128;

fn get_unix_timestamp() -> u64 {
    let unixtstamp = Utc::now().timestamp();
    if unixtstamp < 0 {
        0
    } else {
        unixtstamp.try_into().unwrap()
    }
}

pub fn gen() -> KacheSimpleId {
    let random_part: u64 = rand::random::<u32>().into();
    let timestamp: u64 = get_unix_timestamp() - EPOCH_START;
    return (timestamp << 32) + random_part;
}

pub fn gen_long() -> KacheLongId {
    let random_part0: u128 = rand::random::<u64>().into();
    let random_part1: u128 = rand::random::<u32>().into();
    let timestamp: u128 = (get_unix_timestamp() - EPOCH_START).into();
    (timestamp << 96) + (random_part1 << 64) + random_part0
}
