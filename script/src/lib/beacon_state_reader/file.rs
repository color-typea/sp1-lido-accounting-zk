use crate::utils::{read_binary, read_json};
use log;
use sp1_lido_accounting_zk_shared::io::eth_io::{BeaconChainSlot, ReferenceSlot};
use ssz::{Decode, Encode};
use std::io;
use std::path::{Path, PathBuf};
use std::{env, fs};

use sp1_lido_accounting_zk_shared::eth_consensus_layer::{BeaconBlockHeader, BeaconState};

use super::{BeaconStateReader, StateId};

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

    pub fn get_beacon_state_path(&self, state_id: &str) -> PathBuf {
        self.store_location.join(format!("bs_{}.ssz", state_id))
    }

    pub fn get_beacon_block_header_path(&self, state_id: &str) -> PathBuf {
        self.store_location.join(format!("bs_{}_header.json", state_id))
    }

    pub fn exists(path: &Path) -> bool {
        let result = Path::exists(path);
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
    async fn read_beacon_state(&self, state_id: &StateId) -> anyhow::Result<BeaconState> {
        let permanent_state = state_id.get_permanent_str()?;
        let beacon_state_path = self.file_store.get_beacon_state_path(&permanent_state);
        log::info!("Reading BeaconState from file {:?}", beacon_state_path);
        let data = read_binary(beacon_state_path)?;
        BeaconState::from_ssz_bytes(&data)
            .map_err(|decode_err| anyhow::anyhow!("Couldn't decode ssz {:#?}", decode_err))
    }

    async fn read_beacon_block_header(&self, state_id: &StateId) -> anyhow::Result<BeaconBlockHeader> {
        let permanent_state = state_id.get_permanent_str()?;
        let beacon_block_header_path = self.file_store.get_beacon_block_header_path(&permanent_state);
        log::info!("Reading BeaconBlockHeader from file {:?}", &beacon_block_header_path);
        let res: BeaconBlockHeader = read_json(&beacon_block_header_path)?;
        Ok(res)
    }

    async fn find_bc_slot_for_refslot(&self, _target_slot: ReferenceSlot) -> anyhow::Result<BeaconChainSlot> {
        panic!(
            "File bs reader cannot be used to find beacon chain slot for reference slot - please use RPC or RPC cached"
        );
    }
}

pub struct FileBeaconStateWriter {
    file_store: FileBasedBeaconChainStore,
}

impl FileBeaconStateWriter {
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

        fs::write(self.file_store.get_beacon_state_path(&bs.slot.to_string()), serialized)
            .map_err(|write_err| anyhow::anyhow!("Couldn't write ssz {:#?}", write_err))
    }

    pub fn write_beacon_block_header(&self, bh: &BeaconBlockHeader) -> anyhow::Result<()> {
        self.file_store
            .ensure_exists()
            .map_err(|io_err| anyhow::anyhow!("Couldn't create folders {:#?}", io_err))?;
        let mut serialized: Vec<u8> = Vec::new();
        serde_json::to_writer(&mut serialized, &bh)
            .map_err(|serde_err| anyhow::anyhow!("Couldn't decode ssz {:#?}", serde_err))?;
        fs::write(
            self.file_store.get_beacon_block_header_path(&bh.slot.to_string()),
            serialized,
        )
        .map_err(|write_err| anyhow::anyhow!("Couldn't write ssz {:#?}", write_err))
    }
}
