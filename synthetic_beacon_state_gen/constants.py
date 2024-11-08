# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#misc
FAR_FUTURE_EPOCH = 2 ** 64 - 1
JUSTIFICATION_BITS_LENGTH = 4
MAX_VALIDATORS_PER_COMMITTEE = 2 ** 11
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#time-parameters-1
MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 2**8
SHARD_COMMITTEE_PERIOD = 256
MIN_ATTESTATION_INCLUSION_DELAY = 2**0
SLOTS_PER_EPOCH = 2**5
MIN_SEED_LOOKAHEAD = 2**0
MAX_SEED_LOOKAHEAD = 2**2
MIN_EPOCHS_TO_INACTIVITY_PENALTY = 2**2
EPOCHS_PER_ETH1_VOTING_PERIOD = 2**6
SLOTS_PER_HISTORICAL_ROOT = 2**13
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#state-list-lengths
EPOCHS_PER_HISTORICAL_VECTOR = 2**16
EPOCHS_PER_SLASHINGS_VECTOR = 2**13
HISTORICAL_ROOTS_LIMIT = 2**24
VALIDATOR_REGISTRY_LIMIT = 2**40
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#rewards-and-penalties
PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = 3
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#gwei-values
EFFECTIVE_BALANCE_INCREMENT = 2 ** 0 * 10 ** 9
MAX_EFFECTIVE_BALANCE = 32 * 10 ** 9
# https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#execution
MAX_WITHDRAWALS_PER_PAYLOAD = 2 ** 4
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#withdrawal-prefixes
ETH1_ADDRESS_WITHDRAWAL_PREFIX = '0x01'
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator-cycle
MIN_PER_EPOCH_CHURN_LIMIT = 2 ** 2
CHURN_LIMIT_QUOTIENT = 2 ** 16
# https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#max-operations-per-block
MAX_ATTESTATIONS = 2 ** 7

# https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#sync-committee
SYNC_COMMITTEE_SIZE = 2 ** 9
BYTES_PER_LOGS_BLOOM = 2 ** 8
MAX_EXTRA_DATA_BYTES = 2 ** 5

SLOTS_PER_EPOCH = 2**5