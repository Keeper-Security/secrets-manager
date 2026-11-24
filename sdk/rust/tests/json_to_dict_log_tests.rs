// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Secrets Manager
// Copyright 2024 Keeper Security Inc.
// Contact: sm@keepersecurity.com
//

// Own test binary: the global logger can be installed only once per process.

use keeper_secrets_manager_core::utils::json_to_dict;
use log::{LevelFilter, Log, Metadata, Record};
use std::sync::Mutex;

static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct CaptureLogger;

impl Log for CaptureLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        CAPTURED.lock().unwrap().push(record.args().to_string());
    }
    fn flush(&self) {}
}

static LOGGER: CaptureLogger = CaptureLogger;

#[test]
fn json_to_dict_does_not_log_the_decoded_value() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Trace);

    let marker = "S3cr3t-Pa55w0rd!";
    let result = json_to_dict(&format!("\"{}\"", marker));

    assert!(result.is_none());
    let lines = CAPTURED.lock().unwrap().clone();
    assert!(
        lines.iter().any(|l| !l.is_empty()),
        "expected a warning to be logged"
    );
    for line in &lines {
        assert!(!line.contains(marker), "log line leaks value: {}", line);
    }
}
