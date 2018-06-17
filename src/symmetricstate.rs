use constants::{ASKLEN, CIPHERKEYLEN, MAXHASHLEN};
use types::Hash;
use cipherstate::CipherState;
use error::{SnowError, StateProblem};

use std::collections::HashMap;

#[derive(Copy, Clone)]
struct Inner {
    h       : [u8; MAXHASHLEN],
    ck      : [u8; MAXHASHLEN],
    has_key : bool,
    ask_master: Option<[u8; MAXHASHLEN]>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            h: [0u8; MAXHASHLEN],
            ck: [0u8; MAXHASHLEN],
            has_key: false,
            ask_master: None,
        }
    }
}

pub struct SymmetricState {
    cipherstate : CipherState,
    hasher      : Box<dyn Hash>,
    inner       : Inner,
    checkpoint  : Inner,
    enable_ask  : bool,
    ask_chains  : Option<HashMap<String, Option<[u8; MAXHASHLEN]>>>,
}

impl SymmetricState {
    pub fn new(cipherstate: CipherState, hasher: Box<Hash>, enable_ask: bool) -> SymmetricState {
        SymmetricState {
            cipherstate,
            hasher,
            inner: Inner::default(),
            checkpoint: Inner::default(),
            enable_ask: enable_ask,
            ask_chains: None,
        }
    }

    pub fn initialize(&mut self, handshake_name: &str) {
        if handshake_name.len() <= self.hasher.hash_len() {
            copy_slices!(handshake_name.as_bytes(), self.inner.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name.as_bytes());
            self.hasher.result(&mut self.inner.h);
        }
        copy_slices!(&self.inner.h, &mut self.inner.ck);
        self.inner.has_key = false;
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        if self.enable_ask {
            if let None = self.inner.ask_master {
                self.inner.ask_master = Some([0u8; MAXHASHLEN]);
            }
        }

        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.inner.ck[..hash_len], data,
                         self.inner.ask_master.as_mut().map(|a| &mut a[..]),
                         2, &mut hkdf_output.0, &mut hkdf_output.1, &mut []);
        copy_slices!(&hkdf_output.0, &mut self.inner.ck);
        self.cipherstate.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
        self.inner.has_key = true;
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.inner.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.inner.h);
    }

    pub fn mix_key_and_hash(&mut self, data: &[u8]) {
        if self.enable_ask {
            if let None = self.inner.ask_master {
                self.inner.ask_master = Some([0u8; MAXHASHLEN]);
            }
        }

        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.inner.ck[..hash_len], data,
                         self.inner.ask_master.as_mut().map(|a| &mut a[..]),
                         3, &mut hkdf_output.0, &mut hkdf_output.1, &mut hkdf_output.2);
        copy_slices!(&hkdf_output.0, &mut self.inner.ck);
        self.mix_hash(&hkdf_output.1[..hash_len]);
        self.cipherstate.set(&hkdf_output.2[..CIPHERKEYLEN], 0);
    }

    pub fn has_key(&self) -> bool {
        self.inner.has_key
    }

    /// Encrypt a message and mixes in the hash of the output
    pub fn encrypt_and_mix_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let hash_len = self.hasher.hash_len();
        let output_len = if self.inner.has_key {
            self.cipherstate.encrypt_ad(&self.inner.h[..hash_len], plaintext, out)
        } else {
            copy_slices!(plaintext, out);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        output_len
    }

    pub fn decrypt_and_mix_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.inner.has_key {
            self.cipherstate.decrypt_ad(&self.inner.h[..hash_len], data, out)?
        } else {
            if out.len() < data.len() {
                return Err(())
            }
            copy_slices!(data, out);
            data.len()
        };
        self.mix_hash(data);
        Ok(payload_len)
    }

    pub fn split(&mut self, child1: &mut CipherState, child2: &mut CipherState) {
        if self.enable_ask {
            if let None = self.inner.ask_master {
                self.inner.ask_master = Some([0u8; MAXHASHLEN]);
            }
        }

        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.inner.ck[..hash_len], &[0u8; 0], self.inner.ask_master.as_mut().map(|a| &mut a[..]), 2,
                         &mut hkdf_output.0,
                         &mut hkdf_output.1,
                         &mut []);
        child1.set(&hkdf_output.0[..CIPHERKEYLEN], 0);
        child2.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
    }

    pub fn checkpoint(&mut self) {
        self.checkpoint = self.inner;
    }

    pub fn rollback(&mut self) {
        self.inner = self.checkpoint;
        self.ask_chains = None;
    }

    pub fn handshake_hash(&self) -> &[u8] {
        let hash_len = self.hasher.hash_len();
        &self.inner.h[..hash_len]
    }

    pub fn create_chains(&mut self, labels: Vec<String>) -> Result<(), SnowError> {
        if !self.enable_ask {
            bail!(StateProblem::ASKNotEnabled);
        }

        if let Some(ask_master) = self.inner.ask_master {
            let hash_len = self.hasher.hash_len();
            let mut ask_chains = HashMap::with_capacity(labels.len());
            for label in labels {
                let label_len = label.as_bytes().len();
                let mut input = Vec::with_capacity(hash_len + label_len);
                input.extend_from_slice(&self.inner.h[..hash_len]);
                input.extend_from_slice(label.as_bytes());
                let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
                self.hasher.hkdf(&ask_master[..hash_len], &input[..hash_len + label_len], None, 2,
                                 &mut hkdf_output.0,
                                 &mut hkdf_output.1,
                                 &mut []);
                ask_chains.insert(label, Some(hkdf_output.0));
            }
            self.ask_chains = Some(ask_chains);
            self.inner.ask_master = None;
            Ok(())
        } else {
            bail!(StateProblem::ASKMasterKeyNotReady)
        }
    }

    pub fn invoke_chain(&mut self, label: &String, out: &mut [u8]) -> Result<(), SnowError> {
        if !self.enable_ask {
            bail!(StateProblem::ASKNotEnabled);
        }

        if let Some(ref mut ask_chains) = self.ask_chains {
            match ask_chains.get_mut(label) {
                Some(Some(ref mut ask_ck)) => {
                    let hash_len = self.hasher.hash_len();
                    let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
                    self.hasher.hkdf(&ask_ck[..hash_len], &[0u8; 0], None, 2,
                                     &mut hkdf_output.0,
                                     &mut hkdf_output.1,
                                     &mut []);
                    copy_slices!(&hkdf_output.0, &mut ask_ck[..]);
                    copy_slices!(&hkdf_output.1[..ASKLEN], out);
                    Ok(())
                }
                Some(None) => bail!(StateProblem::ASKChainFinalized),
                None => bail!(SnowError::Input),
            }
        } else {
            bail!(StateProblem::ASKNotInitialized)
        }
    }

    pub fn finish_chain(&mut self, label: &String, out1: &mut [u8], out2: &mut [u8]) -> Result<(), SnowError> {
        if !self.enable_ask {
            bail!(StateProblem::ASKNotEnabled);
        }

        if let Some(ref mut ask_chains) = self.ask_chains {
            if let Some(entry) = ask_chains.get_mut(label) {
                match entry {
                    Some(ask_ck) => {
                        let hash_len = self.hasher.hash_len();
                        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
                        self.hasher.hkdf(&ask_ck[..hash_len], &[0u8; 0], None, 2,
                                        &mut hkdf_output.0,
                                        &mut hkdf_output.1,
                                        &mut []);
                        copy_slices!(&hkdf_output.0[..ASKLEN], out1);
                        copy_slices!(&hkdf_output.1[..ASKLEN], out2);
                    }
                    None => bail!(StateProblem::ASKChainFinalized),
                }
                *entry = None;
                Ok(())
            } else {
                bail!(SnowError::Input)
            }
        } else {
            bail!(StateProblem::ASKNotInitialized)
        }
    }

}
