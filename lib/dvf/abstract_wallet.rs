use async_trait::async_trait;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::Signature;
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_core::types::Address;
use ethers_signers::Ledger;
use ethers_signers::LedgerError;
use ethers_signers::WalletError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AbstractError {
    LedgerError(LedgerError),
    WalletError(WalletError),
}

impl From<LedgerError> for AbstractError {
    fn from(error: LedgerError) -> Self {
        AbstractError::LedgerError(error)
    }
}

impl From<WalletError> for AbstractError {
    fn from(error: WalletError) -> Self {
        AbstractError::WalletError(error)
    }
}

impl std::fmt::Display for AbstractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbstractError::LedgerError(e) => write!(f, "{:?}", e),
            AbstractError::WalletError(e) => write!(f, "{:?}", e),
        }
    }
}

#[derive(Debug)]
pub enum AbstractWallet {
    Ledger(Ledger),
    LocalWallet(LocalWallet),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for AbstractWallet {
    type Error = AbstractError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, AbstractError> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger
                .sign_message(message)
                .await
                .map_err(AbstractError::from),
            AbstractWallet::LocalWallet(localwallet) => localwallet
                .sign_message(message)
                .await
                .map_err(AbstractError::from),
        }
    }

    /// Signs the transaction
    async fn sign_transaction(
        &self,
        message: &TypedTransaction,
    ) -> Result<Signature, AbstractError> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger
                .sign_transaction(message)
                .await
                .map_err(AbstractError::from),
            AbstractWallet::LocalWallet(localwallet) => localwallet
                .sign_transaction(message)
                .await
                .map_err(AbstractError::from),
        }
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, AbstractError> {
        match self {
            AbstractWallet::Ledger(ledger) => ledger
                .sign_typed_data(payload)
                .await
                .map_err(AbstractError::from),
            AbstractWallet::LocalWallet(localwallet) => localwallet
                .sign_typed_data(payload)
                .await
                .map_err(AbstractError::from),
        }
    }

    /// Returns the signer's Ethereum Address
    fn address(&self) -> Address {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.address(),
            AbstractWallet::LocalWallet(localwallet) => localwallet.address(),
        }
    }

    /// Returns the signer's chain id
    fn chain_id(&self) -> u64 {
        match self {
            AbstractWallet::Ledger(ledger) => ledger.chain_id(),
            AbstractWallet::LocalWallet(localwallet) => localwallet.chain_id(),
        }
    }

    /// Sets the signer's chain id
    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        match self {
            AbstractWallet::Ledger(ledger) => {
                AbstractWallet::Ledger(ledger.with_chain_id(chain_id))
            }
            AbstractWallet::LocalWallet(localwallet) => {
                AbstractWallet::LocalWallet(localwallet.with_chain_id(chain_id))
            }
        }
    }
}
