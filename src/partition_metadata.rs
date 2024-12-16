/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Context: CRLite system consists of 2 directories /known and /revoked, collected
* by crlite-fetch service. Each CRLite key contains information about a certificate
* issued by different CA.
* */

/* This module determines the partition to a single issuer file. */
type Timestamp = u64;
const META_SIZE: u64 = 80 * 8;
pub type Partition = Vec<u64>;

/* Information needed for per-issuer partition */
#[derive(Debug)]
pub struct PartitionRecord {
    pub time: Timestamp, /* notAfter time, truncated by hour */
    pub n: u64,
    pub r: u64,
}

impl PartitionRecord {
    pub fn new(time: Timestamp, n: u64, r: u64) -> Self {
        PartitionRecord { time, n, r }
    }
}

pub fn log2(num: f64) -> f64 {
    if num == 0.0 {
        0.0
    } else {
        num.log2()
    }
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
pub fn partition_metadata(records: Vec<PartitionRecord>) -> (Vec<u64>, u64) {
    let len = records.len();
    if records.is_empty() {
        return (Vec::new(), 0);
    }
    let mut dp = vec![(0, 0); len];

    dp[0] = (cost(records[0].r, records[0].n), 0);
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
            }
        }
    }

    // Build metadata
    let mut partition_meta = Vec::<u64>::new();
    let mut left_partition_point = dp[len - 1].1;
    loop {
        if left_partition_point == 0 {
            break;
        };

        partition_meta.push(records[left_partition_point].time);
        left_partition_point = dp[left_partition_point - 1].1;
    }

    partition_meta.reverse();

    (partition_meta, dp[len - 1].0)
}
