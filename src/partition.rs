/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* The partition file takes input of format
 *  unix_timestamp, n, r,
 * where the timestamp is notAfter date of a set of certificates */

type Timestamp = u64;
const META_SIZE: u64 = 80 * 8;

#[derive(Debug)]
pub struct PartitionRecord {
    pub time: Timestamp,
    pub n: u64,
    pub r: u64,
}

impl PartitionRecord {
    pub fn new(time: Timestamp, n: u64, r: u64) -> Self {
        PartitionRecord { time, n, r }
    }
}

pub type PartitionMetadata = Vec<u64>;

pub fn log2(num: f64) -> f64 {
    if num == 0.0 {
        0.0
    } else {
        num.log2()
    }
}

fn size_lower_bound_bytes(ok_count: usize, revoked_count: usize) -> f64 {
    let r = revoked_count as f64;
    let n = (ok_count + revoked_count) as f64;
    let entropy = if revoked_count == 0 || ok_count == 0 {
        0.0
    } else {
        let p = r / n;
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    };
    // Any function that can encode an arbitrary r element subset of an n element set needs
    // an output of length ~log(n choose r) bits. Stirling's approximation to n! implies
    // that log(n choose r) can be approximated by n*H(r/n) where H is the binary entropy
    // function.
    n * entropy / 8.0
}

pub fn cost(r: u64, n: u64) -> u64 {
    let r = r.min(n - r);
    if r == 0 {
        return META_SIZE;
    }

    let rank = if 2 * r < n {
        log2((n - r) as f64 / r as f64).floor() as u64
    } else {
        0
    };

    r * rank + r + ((n - r) >> rank) + META_SIZE
}

/* S: the set of revoked certificates we want to encode
*  Universe: all certificates in the range [timestamp, timestamp] where the time
*  stamp is the issued time of certificate. */
pub fn partition(records: Vec<PartitionRecord>) -> PartitionMetadata {
    let len = records.len();
    assert!(!records.is_empty(), "records must be nonempty");
    let mut dp = vec![(0, 0); len];
    let mut lower_bound = vec![0.0; len];

    // dp[i] = (min cost of partitioning records[0..i], left partition index)
    dp[0] = (cost(records[0].r, records[0].n), 0);
    lower_bound[0] = size_lower_bound_bytes(records[0].n as usize, records[0].r as usize);
    for i in 1..len {
        dp[i] = (u64::MAX, 0);
        let mut r = 0;
        let mut n = 0;
        for j in (0..=i).rev() {
            r += records[j].r;
            n += records[j].n;
            let new_cost = if j > 0 {
                cost(r, n) + dp[j - 1].0
            } else {
                cost(r, n)
            };
            if new_cost < dp[i].0 {
                dp[i] = (new_cost, j);
                lower_bound[i] = if j > 0 {
                    size_lower_bound_bytes(n as usize, r as usize) + lower_bound[j-1]
                } else {
                    size_lower_bound_bytes(n as usize, r as usize) 
                }
            }
        }
    }

    let mut r = 0;
    let mut n = 0;
    for record in &records {
        r += record.r;
        n += record.n;
    }

    // Build metadata
    let mut partition_meta = PartitionMetadata::new();
    let mut left_partition_point = dp[len - 1].1;
    println!("Expected (cost, lower_bound) before partition is {:?} bytes", (cost(r, n) / 8, size_lower_bound_bytes(n as usize, r as usize)));
    println!(
        "Expected (cost, lower_bound) after partition is {:?} bytes",
        (dp[len-1].0 / 8, lower_bound[len-1])
    );
    loop {
        if left_partition_point == 0 {
            partition_meta.push(0);
            break;
        };

        partition_meta.push(records[left_partition_point].time);
        left_partition_point = dp[left_partition_point - 1].1;
    }

    partition_meta.reverse();

    partition_meta
}
