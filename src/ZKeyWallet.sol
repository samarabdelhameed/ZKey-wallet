// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

// 🟢 Importing zkSync system contracts and utilities
import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from '@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IAccount.sol';
import {Transaction, TransactionHelper} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol';
import {EfficientCall} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/EfficientCall.sol';
import {NONCE_HOLDER_SYSTEM_CONTRACT, DEPLOYER_SYSTEM_CONTRACT, INonceHolder} from '@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol';
import {SystemContractsCaller} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractsCaller.sol';
import {Utils} from '@matterlabs/zksync-contracts/l2/system-contracts/libraries/Utils.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';

// 🟢 Importing internal contract dependencies
import {HookManager} from './managers/HookManager.sol';
import {ModuleManager} from './managers/ModuleManager.sol';
import {UpgradeManager} from './managers/UpgradeManager.sol';
import {TokenCallbackHandler, IERC165} from './helpers/TokenCallbackHandler.sol';
import {Errors} from './libraries/Errors.sol';
import {SignatureDecoder} from './libraries/SignatureDecoder.sol';
import {ERC1271Handler} from './handlers/ERC1271Handler.sol';
import {Call} from './batch/BatchCaller.sol';

// 🟢 Importing the account interface for ZKeyWallet
import {IZKeyAccount} from './interfaces/IZKey.sol';

/**
 * @title ZKeyWallet - Smart Wallet for the zkSync Era
 * @dev This contract implements a smart contract wallet with support for EIP-4337.
 */
contract ZKeyWallet is 
    Initializable,       // Supports upgradeable contracts
    UpgradeManager,      // Handles contract upgrades
    HookManager,         // Manages pre- and post-execution hooks
    ModuleManager,       // Manages additional wallet modules
    ERC1271Handler,      // Implements EIP-1271 for signature verification
    TokenCallbackHandler,// Handles ERC20/ERC721/ERC1155 token callbacks
    IZKeyAccount         // Implements the smart account interface
{
    using TransactionHelper for Transaction;

    // 🟢 Immutable address for the batch transaction executor
    address private immutable _BATCH_CALLER;

    /**
     * @notice Constructor that initializes the batch transaction executor address
     * @param batchCaller The address of the contract responsible for handling batched transactions
     */
    constructor(address batchCaller) {
        _BATCH_CALLER = batchCaller;
        _disableInitializers(); // Disables re-initialization to prevent accidental re-deployment
    }

    /**
     * @notice Initializes the smart wallet with an owner, validator, and enabled modules.
     * @param initialR1Owner The initial owner of the wallet (ECDSA public key)
     * @param initialR1Validator The validator responsible for signing transactions
     * @param modules An array of modules that will be enabled for this wallet
     * @param initCall A transaction to execute immediately upon wallet creation
     */
    function initialize(
        bytes calldata initialR1Owner,
        address initialR1Validator,
        bytes[] calldata modules,
        Call calldata initCall
    ) external initializer {
        _r1AddOwner(initialR1Owner);
        _r1AddValidator(initialR1Validator);

        for (uint256 i = 0; i < modules.length; ) {
            _addModule(modules[i]);
            unchecked { i++; }
        }

        if (initCall.target != address(0)) {
            uint128 value = Utils.safeCastToU128(initCall.value);
            _executeCall(initCall.target, value, initCall.callData, initCall.allowFailure);
        }
    }

    // 🟢 Allows the wallet to receive ETH
    receive() external payable {}

    /**
     * @notice Validates a transaction before execution.
     * @dev Ensures that the wallet agrees to process the transaction and has sufficient balance.
     * @param suggestedSignedHash The suggested transaction hash signed by the owner
     * @param transaction The transaction details
     * @return magic A validation magic number if the transaction is valid
     */
    function validateTransaction(
        bytes32,
        bytes32 suggestedSignedHash,
        Transaction calldata transaction
    ) external payable override onlyBootloader returns (bytes4 magic) {
        _incrementNonce(transaction.nonce);

        // Ensure the wallet has enough balance to process the transaction
        if (transaction.totalRequiredBalance() > address(this).balance) {
            revert Errors.INSUFFICIENT_FUNDS();
        }

        // Calculate the signed transaction hash
        bytes32 signedHash = suggestedSignedHash == bytes32(0)
            ? transaction.encodeHash()
            : suggestedSignedHash;

        magic = _validateTransaction(signedHash, transaction);
    }

    /**
     * @notice Executes a transaction from the bootloader.
     * @param transaction The transaction to execute
     */
    function executeTransaction(
        bytes32,
        bytes32,
        Transaction calldata transaction
    ) external payable override onlyBootloader {
        _executeTransaction(transaction);
    }

    /**
     * @notice Allows external execution of transactions (by an externally owned account).
     * @dev Ensures the sender is authorized before executing.
     * @param transaction The transaction to execute
     */
    function executeTransactionFromOutside(Transaction calldata transaction) 
        external payable override 
    {
        if (!_k1IsOwner(msg.sender)) {
            revert Errors.UNAUTHORIZED_OUTSIDE_TRANSACTION();
        }

        // Extract validation hooks from the signature
        bytes[] memory hookData = SignatureDecoder.decodeSignatureOnlyHookData(
            transaction.signature
        );

        // Compute the transaction hash
        bytes32 signedHash = transaction.encodeHash();

        // Run validation hooks to check conditions before execution
        if (!runValidationHooks(signedHash, transaction, hookData)) {
            revert Errors.VALIDATION_HOOK_FAILED();
        }

        _executeTransaction(transaction);
    }

    /**
     * @notice Allows the wallet to pay for its own gas if no paymaster is involved.
     * @param transaction The transaction for which gas fees need to be covered
     */
    function payForTransaction(
        bytes32,
        bytes32,
        Transaction calldata transaction
    ) external payable override onlyBootloader {
        bool success = transaction.payToTheBootloader();
        if (!success) {
            revert Errors.FEE_PAYMENT_FAILED();
        }
        emit FeePaid();
    }

    /**
     * @notice Executes the transaction logic internally.
     * @dev Ensures the transaction is processed correctly based on the specified execution hooks.
     * @param transaction The transaction data
     */
    function _executeTransaction(Transaction calldata transaction) 
        internal runExecutionHooks(transaction) 
    {
        address to = _safeCastToAddress(transaction.to);
        uint128 value = Utils.safeCastToU128(transaction.value);
        bytes calldata data = transaction.data;
        _executeCall(to, value, data, false);
    }

    /**
     * @dev Casts a uint256 to an Ethereum address safely.
     * @param value The value to be cast to an address
     * @return The resulting address
     */
    function _safeCastToAddress(uint256 value) internal pure returns (address) {
        if (value > type(uint160).max) revert();
        return address(uint160(value));
    }
}
