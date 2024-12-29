/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This program takes a revoked directory path and a known directory path, then
* performs the partition of files on disk and output the serialized partition metadata
* */

use clubcard_crlite::partition::PartitionBuilder;
use std::env::{args, current_dir};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> std::process::ExitCode {
    let mut args = args();
    let _program_path = args.next().unwrap();

    let revoked_dir = PathBuf::from(args.next().expect("Expect revoked directory path"));
    let known_dir = PathBuf::from(args.next().expect("Expect known directory path"));
    let output_partition_revoked_dir = PathBuf::from(
        args.next()
            .expect("Expect directory path for revoked certificates"),
    );
    let output_partition_known_dir = PathBuf::from(
        args.next()
            .expect("Expect directory path for partitioned known certificates"),
    );
    let meta_path = if let Some(path) = args.next() {
        PathBuf::from(path)
    } else {
        current_dir()
            .expect("Expect current directory")
            .join("serialized_meta")
    };
    let mut meta_file = File::create(&meta_path).unwrap();

    let partition_builder = PartitionBuilder::new(&revoked_dir, &known_dir, &output_partition_revoked_dir, &output_partition_known_dir);
    let partition_metadata = partition_builder.partition_directory();
    let bytes = meta_file
        .write(&bincode::serialize(&partition_metadata).unwrap())
        .unwrap();

    println!("Write {bytes} meta data to {meta_path:?}");

    ExitCode::SUCCESS
}
