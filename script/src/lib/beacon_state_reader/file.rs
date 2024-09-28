use crate::utils::{read_binary, read_json};
use log;
use ssz::{Decode, Encode};
use std::io;
use std::path::{Path, PathBuf};
use std::{env, fs};

use sp1_lido_accounting_zk_shared::eth_consensus_layer::{BeaconBlockHeader, BeaconState};

use super::BeaconStateReader;

pub struct FileBasedBeaconChainStore {
    pub store_location: PathBuf,
}

impl FileBasedBeaconChainStore {
    pub fn new(store_location: &Path) -> Self {
        let abs_path = Self::abs_path(PathBuf::from(store_location))
            .unwrap_or_else(|_| panic!("Failed to convert {} into absolute path", store_location.display()));
        Self {
            store_location: abs_path,
        }
    }

    fn abs_path(path: PathBuf) -> io::Result<PathBuf> {
        if path.is_absolute() {
            Ok(path)
        } else {
            Ok(env::current_dir()?.join(path))
        }
    }

    pub fn get_beacon_state_path(&self, slot: u64) -> PathBuf {
        self.store_location.join(format!("bs_{}.ssz", slot))
    }

    pub fn get_beacon_block_header_path(&self, slot: u64) -> PathBuf {
        self.store_location.join(format!("bs_{}_header.json", slot))
    }

    pub fn exists(path: &Path) -> bool {
        let result = Path::exists(&path);
        if result {
            log::debug!("Path exists {:?}", path);
        } else {
            log::debug!("Path does not exist ({:?})", path);
        }
        result
    }

    pub fn ensure_exists(&self) -> io::Result<()> {
        std::fs::create_dir_all(self.store_location.clone())
    }

    pub fn delete(path: &Path) -> io::Result<()> {
        fs::remove_file(path)?;
        Ok(())
    }
}

pub struct FileBasedBeaconStateReader {
    file_store: FileBasedBeaconChainStore,
}

impl FileBasedBeaconStateReader {
    pub fn new(store_location: &Path) -> Self {
        Self {
            file_store: FileBasedBeaconChainStore::new(store_location),
        }
    }
}

impl BeaconStateReader for FileBasedBeaconStateReader {
    async fn read_beacon_state(&self, slot: u64) -> anyhow::Result<BeaconState> {
        let beacon_state_path = self.file_store.get_beacon_state_path(slot);
        log::info!("Reading BeaconState from file {:?}", beacon_state_path);
        let data = read_binary(beacon_state_path)?;
        // TODO: better mapping ssz::DecodeError to std::error::Error/anyhow::Error
        BeaconState::from_ssz_bytes(&data)
            .map_err(|decode_err| anyhow::anyhow!("Couldn't decode ssz {:#?}", decode_err))
    }

    async fn read_beacon_block_header(&self, slot: u64) -> anyhow::Result<BeaconBlockHeader> {
        let beacon_block_header_path = self.file_store.get_beacon_block_header_path(slot);
        log::info!("Reading BeaconBlock from file {:?}", &beacon_block_header_path);
        let res: BeaconBlockHeader = read_json(&beacon_block_header_path)?;
        Ok(res)
    }
}

pub struct FileBeaconStateWriter {
    file_store: FileBasedBeaconChainStore,
}

impl FileBeaconStateWriter {
    // TODO: refactor so reader and writer can use the same store not two identical copies
    pub fn new(store_location: &Path) -> Self {
        Self {
            file_store: FileBasedBeaconChainStore::new(store_location),
        }
    }

    pub fn write_beacon_state(&self, bs: &BeaconState) -> anyhow::Result<()> {
        self.file_store
            .ensure_exists()
            .map_err(|io_err| anyhow::anyhow!("Couldn't create folders {:#?}", io_err))?;

        let serialized = bs.as_ssz_bytes();

        fs::write(self.file_store.get_beacon_state_path(bs.slot), serialized)
            .map_err(|write_err| anyhow::anyhow!("Couldn't write ssz {:#?}", write_err))
    }

    pub fn write_beacon_block_header(&self, bh: &BeaconBlockHeader) -> anyhow::Result<()> {
        self.file_store
            .ensure_exists()
            .map_err(|io_err| anyhow::anyhow!("Couldn't create folders {:#?}", io_err))?;
        let mut serialized: Vec<u8> = Vec::new();
        serde_json::to_writer(&mut serialized, &bh)
            .map_err(|serde_err| anyhow::anyhow!("Couldn't decode ssz {:#?}", serde_err))?;
        fs::write(self.file_store.get_beacon_block_header_path(bh.slot), serialized)
            .map_err(|write_err| anyhow::anyhow!("Couldn't write ssz {:#?}", write_err))
    }
}
