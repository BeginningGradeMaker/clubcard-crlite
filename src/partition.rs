/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This program provides utilities that takes inputs <revoked_dir> and <known_dir>,
* and splits each file based on the metadata */

extern crate base64;
extern crate hex;
use crate::partition_metadata::{partition_metadata, Partition, PartitionRecord};
use base64::Engine;
use clubcard::ApproximateSizeOf;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Lines, Write};
use std::path::{Path, PathBuf};

type IssuerSPKIHash = [u8; 32];
#[derive(Default, Serialize, Deserialize)]
pub struct PartitionIndex(pub HashMap<IssuerSPKIHash, Partition>);

impl From<()> for PartitionIndex {
    fn from(_: ()) -> Self {
        Default::default()
    }
}

impl PartitionIndex {
    pub fn partition_index(&self, issuer: &[u8; 32], not_after: u64) -> Option<usize> {
        let partition = self.0.get(issuer)?;

        let partition_idx = match partition.binary_search_by(|&some_not_after| {
            if some_not_after > not_after {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        }) {
            Ok(pos) => pos, // this happens when a greater value is directly found
            _ => partition.len(),
        };

        Some(partition_idx)
    }
}

impl ApproximateSizeOf for PartitionIndex {
    fn approximate_size_of(&self) -> usize {
        size_of::<Self>()
    }
}

struct RevokedSerialAndReasonIterator {
    lines: Option<Lines<BufReader<File>>>,
}

impl RevokedSerialAndReasonIterator {
    fn new(path: &Path) -> Self {
        Self {
            lines: Some(BufReader::new(File::open(path).unwrap()).lines()),
        }
    }

    //fn empty() -> Self {
    //    Self { lines: None }
    //}
}

impl Iterator for RevokedSerialAndReasonIterator {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut line) = self.lines.as_mut()?.next().transpose().expect("IO error") {
            let serial = line.split_off(2);
            return Some(decode_serial(&serial));
        }
        None
    }
}

struct KnownSerialIterator {
    lines: Lines<BufReader<File>>,
    date: u64,
}

impl KnownSerialIterator {
    fn new(path: &Path) -> Self {
        Self {
            lines: BufReader::new(File::open(path).unwrap()).lines(),
            date: 0,
        }
    }
}

impl Iterator for KnownSerialIterator {
    type Item = (u64, String);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(line) = self.lines.next().transpose().expect("io error") {
            if let Some(timestamp) = line.strip_prefix("@") {
                self.date = u64::from_str_radix(timestamp, 16).expect("malformed date");
                continue;
            }
            return Some((self.date, line));
        }
        None
    }
}

fn decode_serial(s: &str) -> Vec<u8> {
    hex::decode(s.as_bytes()).expect("found invalid serial number: not ascii hex.")
}

pub struct PartitionBuilder {
    revoked_dir: PathBuf,
    known_dir: PathBuf,
    partition_revoked_dir: PathBuf,
    partition_known_dir: PathBuf,
    approx_size: u64,
}

impl PartitionBuilder {
    pub fn new(
        revoked_dir: &Path,
        known_dir: &Path,
        partition_revoked_dir: &Path,
        partition_known_dir: &Path,
    ) -> Self {
        Self {
            revoked_dir: revoked_dir.to_path_buf(),
            known_dir: known_dir.to_path_buf(),
            partition_revoked_dir: partition_revoked_dir.to_path_buf(),
            partition_known_dir: partition_known_dir.to_path_buf(),
            approx_size: 0,
        }
    }

    pub fn list_issuer_file_pairs(&self) -> Vec<(OsString, Option<PathBuf>, PathBuf)> {
        let known_files = Path::read_dir(&self.known_dir).unwrap();
        let known_issuers: Vec<OsString> = known_files
            .filter_map(|x| x.ok())
            .map(|x| x.file_name())
            .collect();

        let mut pairs = vec![];
        for issuer in known_issuers {
            let k_file = self.known_dir.join(&issuer);
            let r_file = self.revoked_dir.join(&issuer);
            if r_file.exists() {
                pairs.push((issuer, Some(r_file), k_file));
            } else {
                pairs.push((issuer, None, k_file));
            }
        }

        pairs
    }

    fn decode_issuer(&self, s: &str) -> [u8; 32] {
        //println!("{s}");
        base64::prelude::BASE64_URL_SAFE
            .decode(s)
            .expect("found invalid issuer id: not url-safe base64.")
            .try_into()
            .expect("found invalid issuer id: not 32 bytes.")
    }

    fn partition_issuer(
        &mut self,
        issuer: OsString,
        maybe_revoked_file: Option<PathBuf>,
        known_file: PathBuf,
    ) -> Option<Vec<u64>> {
        // if there is no revoked file, no partition is needed
        let Some(revoked_file) = maybe_revoked_file else {
            let _ = fs::copy(known_file, self.partition_known_dir.join(&issuer));
            return None;
        };

        // count the number of revoked and known certificates for each timestamp
        let known_lines = KnownSerialIterator::new(&known_file);
        let mut serial_to_timestamp = HashMap::<Vec<u8>, u64>::new();
        let mut universe_count = BTreeMap::<u64, (HashSet<Vec<u8>>, HashSet<Vec<u8>>)>::new();
        for line in known_lines {
            let timestamp = line.0;
            let serial = decode_serial(&line.1);
            serial_to_timestamp.insert(serial.clone(), timestamp);
            universe_count
                .entry(timestamp)
                .or_default()
                .0
                .insert(serial);
        }

        let revoked_lines = RevokedSerialAndReasonIterator::new(&revoked_file);
        for serial in revoked_lines {
            if let Some(timestamp) = serial_to_timestamp.get(&serial) {
                universe_count
                    .get_mut(timestamp)
                    .expect("Timestamp occured in revoked file but not in known file")
                    .1
                    .insert(serial);
            }
        }

        let mut partition_records = Vec::new();
        for (timestamp, (known_set, revoked_set)) in &universe_count {
            partition_records.push(PartitionRecord::new(
                *timestamp,
                known_set.len() as u64,
                revoked_set.len() as u64,
            ));
        }

        let (partition, approx_size) = partition_metadata(partition_records);
        self.approx_size += approx_size;
        let partition_len = partition.len();
        if partition_len == 0 {
            // copy the un-partitioned file to the output directory.
            let _ = fs::copy(known_file, self.partition_known_dir.join(&issuer)).unwrap();
            let _ = fs::copy(revoked_file, self.partition_revoked_dir.join(&issuer)).unwrap();
            return None;
        }

        let mut partition_idx = 0;
        let create_partition_writer = |dir: &Path, partition_idx: usize| -> BufWriter<File> {
            let mut issuer_bytes = self.decode_issuer(issuer.to_str().unwrap()).to_vec();
            issuer_bytes.push(partition_idx as u8);
            BufWriter::new(
                File::create(dir.join(base64::prelude::BASE64_URL_SAFE.encode(issuer_bytes)))
                    .unwrap(),
            )
        };

        let mut known_writer = create_partition_writer(&self.partition_known_dir, partition_idx);
        for (timestamp, (known_set, _)) in &universe_count {
            while partition_idx < usize::min(partition_len, 255)
                && *timestamp > partition[partition_idx]
            {
                partition_idx += 1;
                let _ = known_writer.flush();
                known_writer = create_partition_writer(&self.partition_known_dir, partition_idx);
            }
            let _ =
                known_writer.write(("@".to_string() + &format!("{:016x}\n", timestamp)).as_bytes());
            for serial in known_set {
                let _ = known_writer.write(hex::encode(serial).as_bytes());
                let _ = known_writer.write(b"\n");
            }
        }

        partition_idx = 0;
        let mut known_writer = create_partition_writer(&self.partition_revoked_dir, partition_idx);
        for (timestamp, (_, revoked_set)) in &universe_count {
            while partition_idx < usize::min(partition_len, 255)
                && *timestamp > partition[partition_idx]
            {
                partition_idx += 1;
                let _ = known_writer.flush();
                known_writer = create_partition_writer(&self.partition_revoked_dir, partition_idx);
            }
            for serial in revoked_set {
                let _ = known_writer.write(hex::encode(serial).as_bytes());
                let _ = known_writer.write(b"\n");
            }
        }

        Some(partition)
    }

    pub fn partition_directory(&mut self) -> PartitionIndex {
        let pairs = self.list_issuer_file_pairs();
        let mut metadata = PartitionIndex::default();

        for (issuer, maybe_revoked_file, known_file) in pairs {
            if let Some(partition) =
                self.partition_issuer(issuer.clone(), maybe_revoked_file, known_file)
            {
                metadata
                    .0
                    .insert(self.decode_issuer(issuer.to_str().unwrap()), partition);
            }
        }

        println!(
            "The approximated size after partition is {}",
            self.approx_size
        );
        metadata
    }
}
