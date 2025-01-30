use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use alloy::primitives::Address;
use tracing::debug;

use crate::dvf::config::DVFConfig;
use crate::dvf::parse::CompleteDVF;
use crate::dvf::parse::ValidationError;
use crate::utils::pretty::{AddressType, ResolvedAddress};

pub struct Registry {
    dvf_storage: PathBuf,
    trusted_signers: Vec<Address>,
}

impl Registry {
    pub fn from_config(config: &DVFConfig) -> Result<Self, ValidationError> {
        let dvf_storage = config.dvf_storage.clone();

        Ok(Registry {
            dvf_storage,
            trusted_signers: config.trusted_signers.clone(),
        })
    }

    pub fn is_trusted_signer(&self, address: &Address) -> bool {
        self.trusted_signers.contains(address)
    }

    pub fn collect_name_resolution(&self, chain_id: u64) -> HashMap<Address, ResolvedAddress> {
        let mut res: HashMap<Address, ResolvedAddress> = HashMap::new();
        self.collect_names_inner(&self.dvf_storage, &mut res, chain_id);
        res
    }

    fn collect_names_inner(
        &self,
        dir: &Path,
        res: &mut HashMap<Address, ResolvedAddress>,
        chain_id: u64,
    ) {
        let rdir = match fs::read_dir(dir) {
            Ok(rdir) => rdir,
            Err(_) => return,
        };
        for entry in rdir {
            if entry.is_err() {
                continue;
            }
            let path = entry.unwrap().path();

            if path.is_file() && Some(OsStr::new("json")) == path.extension() {
                if let Some(found_dvf) = self.open_and_validate_trusted_signer(&path) {
                    if chain_id != found_dvf.chain_id {
                        continue;
                    }
                    res.insert(
                        found_dvf.address,
                        ResolvedAddress {
                            address_type: AddressType::Registry,
                            name: found_dvf.contract_name,
                        },
                    );
                }
            } else if path.is_dir() {
                self.collect_names_inner(&path, res, chain_id);
            }
        }
    }

    fn open_and_validate_trusted_signer(&self, f: &Path) -> Option<CompleteDVF> {
        let filled = match CompleteDVF::from_path(f) {
            Ok(f) => f,
            Err(e) => {
                debug!("Error when opening {}: {:?}", f.display(), e);
                return None;
            }
        };
        if let Some(e) = filled.validate_id().err() {
            debug!("Error when validating id of {}: {:?}.", f.display(), e);
            return None;
        };
        if let Some(e) = filled.validate_signature(true).err() {
            debug!("Error when validating id of {}: {:?}.", f.display(), e);
            return None;
        };
        if !self.is_trusted_signer(&filled.signature.as_ref().unwrap().signer) {
            debug!("Untrusted signer for {}.", f.display());
            return None;
        }
        Some(filled)
    }

    pub fn find_dvf_by_id(&self, id: &String) -> Result<Vec<PathBuf>, ValidationError> {
        search_for_id(&self.dvf_storage, id)
    }

    pub fn find_dvf_by_address(&self, address: &String) -> Result<Vec<PathBuf>, ValidationError> {
        let mut results = Vec::new();

        for entry in fs::read_dir(&self.dvf_storage)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file()
                && path
                    .file_name()
                    .is_some_and(|f| f.to_string_lossy().contains(address))
            {
                results.push(path);
            }
        }
        Ok(results)
    }
}

// Recursive function to copy files
// fn rec_copy_files(src: &Path, dest: &Path) -> io::Result<()> {
//     if src.is_dir() {
//         if !dest.exists() {
//             fs::create_dir_all(dest)?;
//         }
//         for entry_result in fs::read_dir(src)? {
//             let entry = entry_result?;
//             let entry_path = entry.path();
//             let dest_path = dest.join(entry.file_name());
//             if entry_path.is_dir() {
//                 rec_copy_files(&entry_path, &dest_path)?;
//             } else {
//                 fs::copy(&entry_path, &dest_path)?;
//             }
//         }
//     } else {
//         fs::copy(src, dest)?;
//     }
//     Ok(())
// }

fn open_and_compute_id(f: &Path) -> Option<String> {
    let filled = match CompleteDVF::from_path(f) {
        Ok(f) => f,
        Err(e) => {
            debug!("Error when opening {}: {:?}", f.display(), e);
            return None;
        }
    };
    match filled.validate_id() {
        Ok(()) => Some(filled.id.clone().unwrap()),
        Err(e) => {
            debug!("Error when validating id of {}: {:?}.", f.display(), e);
            None
        }
    }
}

fn search_for_id(dir: &Path, id: &String) -> Result<Vec<PathBuf>, ValidationError> {
    let mut results: Vec<PathBuf> = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file()
            && Some(OsStr::new("json")) == path.extension()
            && Some(id.clone()) == open_and_compute_id(&path)
        {
            results.push(path);
        } else if path.is_dir() {
            let mut subresults = search_for_id(&path, id)?;
            results.append(&mut subresults);
        }
    }
    Ok(results)
}
