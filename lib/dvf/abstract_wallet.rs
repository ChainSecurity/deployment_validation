use async_trait::async_trait;

use alloy::consensus::SignableTransaction;
use alloy::dyn_abi::eip712::TypedData;
use alloy::network::TxSigner;
use alloy::primitives::{Address, ChainId, Signature as Signature, B256};
use alloy::signers::local::{LocalSignerError, PrivateKeySigner};
use alloy::signers::{Error as SignerError, Signer};
use alloy::sol_types::{Eip712Domain, SolStruct};
use alloy_signer_ledger::{LedgerError, LedgerSigner};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AbstractError {
    LedgerError(LedgerError),
    WalletError(LocalSignerError),
    GeneralError(SignerError),
}

impl From<LedgerError> for AbstractError {
    fn from(error: LedgerError) -> Self {
        AbstractError::LedgerError(error)
    }
}

impl From<LocalSignerError> for AbstractError {
    fn from(error: LocalSignerError) -> Self {
        AbstractError::WalletError(error)
    }
}

impl From<alloy::signers::Error> for AbstractError {
    fn from(error: SignerError) -> Self {
        AbstractError::GeneralError(error)
    }
}

impl std::fmt::Display for AbstractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbstractError::LedgerError(e) => write!(f, "{:?}", e),
            AbstractError::WalletError(e) => write!(f, "{:?}", e),
            AbstractError::GeneralError(e) => write!(f, "{:?}", e),
        }
    }
}

#[derive(Debug)]
pub enum AbstractWallet {
    Ledger(LedgerSigner),
    LocalWallet(PrivateKeySigner),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl TxSigner<Signature> for AbstractWallet {
    fn address(&self) -> Address {
        match self {
            AbstractWallet::Ledger(ledger) => Signer::address(ledger),
            AbstractWallet::LocalWallet(localwallet) => localwallet.address(),
        }
    }

    #[inline]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature, alloy::signers::Error> {
        //@audit how to turn a typed transaction into a signableTx?
        match self {
            AbstractWallet::Ledger(ledger) => ledger.sign_transaction(tx).await,
            AbstractWallet::LocalWallet(localwallet) => localwallet.sign_transaction(tx).await,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for AbstractWallet {
    async fn sign_hash(&self, _hash: &B256) -> Result<Signature, alloy::signers::Error> {
        Err(alloy_signer::Error::UnsupportedOperation(
            alloy_signer::UnsupportedSignerOperation::SignHash,
        ))
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, alloy::signers::Error> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.sign_message(message).await,
            AbstractWallet::LocalWallet(localwallet) => localwallet.sign_message(message).await,
        }
    }

    #[inline]
    async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> Result<Signature, alloy::signers::Error> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.sign_typed_data(payload, domain).await,
            // .map_err(AbstractError::from),
            AbstractWallet::LocalWallet(localwallet) => {
                localwallet.sign_typed_data(payload, domain).await
            }
        }
    }

    #[inline]
    async fn sign_dynamic_typed_data(
        &self,
        payload: &TypedData,
    ) -> Result<Signature, alloy::signers::Error> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.sign_dynamic_typed_data(payload).await,
            // .map_err(AbstractError::from),
            AbstractWallet::LocalWallet(localwallet) => {
                localwallet.sign_dynamic_typed_data(payload).await
            }
        }
    }

    /// Returns the signer's Ethereum Address
    fn address(&self) -> Address {
        match self {
            AbstractWallet::Ledger(ledger) => Signer::address(ledger),
            AbstractWallet::LocalWallet(localwallet) => localwallet.address(),
        }
    }

    /// Returns the signer's chain id
    fn chain_id(&self) -> Option<ChainId> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.chain_id(),
            AbstractWallet::LocalWallet(localwallet) => localwallet.chain_id(),
        }
    }

    /// Sets the signer's chain id
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.set_chain_id(chain_id),
            AbstractWallet::LocalWallet(localwallet) => localwallet.set_chain_id(chain_id),
        }
    }
}
