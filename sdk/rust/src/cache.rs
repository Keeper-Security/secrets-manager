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

use crate::custom_error::KSMRError;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};

const DEFAULT_FILE_PATH: &str = "ksm_cache.bin";

#[derive(Clone, Debug)]
pub enum KSMCache {
    File(FileCache),
    Memory(MemoryCache),
    None,
}

impl KSMCache {
    pub fn is_none(&self) -> bool {
        // match self {
        //     KSMCache::None => true,
        //     _ => false,
        // }

        matches!(self, KSMCache::None)
    }
}

#[derive(Debug)]
pub struct KSMRCache {
    cache: KSMCache,
}

impl KSMCache {
    pub fn save_cached_value(&mut self, data: &[u8]) -> Result<(), KSMRError> {
        match self {
            KSMCache::File(file_cache) => file_cache.save_cached_value(data),
            KSMCache::Memory(memory_cache) => memory_cache.save_cached_value(data),
            KSMCache::None => Err(KSMRError::CacheSaveError(
                "No cache available for saving data.".to_string(),
            )),
        }
    }

    pub fn get_cached_value(&self) -> Result<Vec<u8>, KSMRError> {
        match self {
            KSMCache::File(file_cache) => file_cache.get_cached_value(),
            KSMCache::Memory(memory_cache) => memory_cache.get_cached_value(),
            KSMCache::None => Err(KSMRError::CacheRetrieveError(
                "No cache available for retrieving data.".to_string(),
            )),
        }
    }

    pub fn purge(&mut self) -> Result<(), KSMRError> {
        match self {
            KSMCache::File(file_cache) => file_cache.purge(),
            KSMCache::Memory(memory_cache) => memory_cache.purge(),
            KSMCache::None => Ok(()), // No-op for None cache
        }
    }
}

impl KSMRCache {
    pub fn new_file_cache(file_path: Option<&str>) -> Result<Self, KSMRError> {
        let file_cache = FileCache::new(file_path.unwrap_or(DEFAULT_FILE_PATH))?;
        Ok(Self {
            cache: KSMCache::File(file_cache),
        })
    }

    /// This is not persistent and is not useful for most use cases, please prefer `new_file_cache` over this implementation.
    pub fn new_memory_cache() -> Result<Self, KSMRError> {
        Ok(Self {
            cache: KSMCache::Memory(MemoryCache::new()),
        })
    }

    pub fn new_none() -> Self {
        Self {
            cache: KSMCache::None,
        }
    }

    pub fn save_cached_value(&mut self, data: &[u8]) -> Result<(), KSMRError> {
        match &mut self.cache {
            KSMCache::File(file_cache) => file_cache.save_cached_value(data),
            KSMCache::Memory(memory_cache) => memory_cache.save_cached_value(data),
            KSMCache::None => Err(KSMRError::CacheSaveError(
                "No cache available for saving data.".to_string(),
            )),
        }
    }

    pub fn get_cached_value(&self) -> Result<Vec<u8>, KSMRError> {
        match &self.cache {
            KSMCache::File(file_cache) => file_cache.get_cached_value(),
            KSMCache::Memory(memory_cache) => memory_cache.get_cached_value(),
            KSMCache::None => Err(KSMRError::CacheRetrieveError(
                "No cache available for retrieving data.".to_string(),
            )),
        }
    }

    pub fn purge(&mut self) -> Result<(), KSMRError> {
        match &mut self.cache {
            KSMCache::File(file_cache) => file_cache.purge(),
            KSMCache::Memory(memory_cache) => memory_cache.purge(),
            KSMCache::None => Ok(()), // No-op for None cache
        }
    }
}

impl From<KSMRCache> for KSMCache {
    fn from(ksmr_cache: KSMRCache) -> Self {
        ksmr_cache.cache
    }
}

impl From<KSMCache> for KSMRCache {
    fn from(ksm_cache: KSMCache) -> Self {
        KSMRCache { cache: ksm_cache }
    }
}

// File-based cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCache {
    file_path: String,
}

impl FileCache {
    pub fn new(file_path: &str) -> Result<Self, KSMRError> {
        let mut path = file_path.trim().to_string();

        if path.is_empty() {
            path = DEFAULT_FILE_PATH.to_string();
        }

        if !Path::new(&path).is_absolute() {
            if let Ok(ksm_cache_dir) = env::var("KSM_CACHE_DIR") {
                let ksm_cache_dir = ksm_cache_dir.trim();
                if !ksm_cache_dir.is_empty() {
                    path = PathBuf::from(ksm_cache_dir)
                        .join(&path)
                        .to_string_lossy()
                        .to_string();
                }
            }
        }
        let mut file_opened = match File::open(path.clone()) {
            Ok(resp) => resp,
            Err(err) => {
                if err.to_string().contains("No such file or directory")
                    || err
                        .to_string()
                        .contains("The system cannot find the file specified")
                {
                    let file = OpenOptions::new()
                    .read(true) // Open for reading
                    .write(true) // Open for writing
                    .create(true) // Create if it doesn't exist
                    .truncate(true)// Overwrite if already existing
                    .open(file_path).map_err(|err| KSMRError::CacheSaveError(format!("Error creating cache file in location mentioned {} and exited with error {}.", file_path,err))).unwrap();
                    file
                } else {
                    panic!("{}", err);
                }
            }
        };

        file_opened.flush().unwrap();

        Ok(FileCache { file_path: path })
    }

    pub fn save_cached_value(&self, data: &[u8]) -> Result<(), KSMRError> {
        let data = if data.is_empty() { &[] } else { data };
        let mut file =
            File::create(&self.file_path).map_err(|e| KSMRError::CacheSaveError(e.to_string()))?;
        file.write_all(data)
            .map_err(|e| KSMRError::CacheSaveError(e.to_string()))?;
        Ok(())
    }

    pub fn get_cached_value(&self) -> Result<Vec<u8>, KSMRError> {
        let mut file = File::open(&self.file_path)
            .map_err(|e| KSMRError::CacheRetrieveError(e.to_string()))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| KSMRError::CacheRetrieveError(e.to_string()))?;
        Ok(data)
    }

    pub fn purge(&self) -> Result<(), KSMRError> {
        if Path::new(&self.file_path).exists() {
            fs::remove_file(&self.file_path)
                .map_err(|e| KSMRError::CachePurgeError(e.to_string()))?;
        }
        Ok(())
    }
}

// In-memory cache
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryCache {
    data: Vec<u8>,
}

impl MemoryCache {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn save_cached_value(&mut self, data: &[u8]) -> Result<(), KSMRError> {
        self.data.clear();
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub fn get_cached_value(&self) -> Result<Vec<u8>, KSMRError> {
        Ok(self.data.clone())
    }

    pub fn purge(&mut self) -> Result<(), KSMRError> {
        self.data.clear();
        Ok(())
    }
}
