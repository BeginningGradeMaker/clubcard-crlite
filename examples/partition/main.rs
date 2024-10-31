/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use clubcard_crlite::partition;
use std::env::args;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

fn parse_args() -> Option<Vec<partition::PartitionRecord>> {
    let mut args = args().map(PathBuf::from);

    let _name = args.next();
    let record_path = args.next()?;
    let mut records = Vec::<partition::PartitionRecord>::new();
    if let Ok(record_file) = File::open(record_path) {
        let reader = io::BufReader::new(record_file);

        for line in reader.lines().map_while(Result::ok) {
            let clean_input = line.replace(',',"");
            let parts = clean_input.split_whitespace().collect::<Vec<&str>>();
            if let (Ok(timestamp), Ok(n), Ok(r)) = (
                parts[0].parse::<u64>(),
                parts[1].parse::<u64>(),
                parts[2].parse::<u64>(),
            ) {
                records.push(partition::PartitionRecord::new(timestamp, n, r));
            }
        }
    }

    Some(records)
}

fn main() -> std::process::ExitCode {
    let records = parse_args().unwrap();

    let metadata = partition::partition(records);
    println!("The partition is {metadata:?} of size {}", metadata.len());

    ExitCode::SUCCESS
}
