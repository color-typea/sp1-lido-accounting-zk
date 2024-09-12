use crate::{circuit_logic::report::ReportData, eth_consensus_layer::Hash256};

use crate::io::eth_io::{
    conversions, LidoValidatorStateSolidity, PublicValuesSolidity, ReportMetadataSolidity, ReportSolidity,
};

pub fn create_public_values(
    report: &ReportData,
    beacon_block_hash: &Hash256,
    old_state_slot: u64,
    old_state_hash: &Hash256,
    new_state_slot: u64,
    new_state_hash: &Hash256,
) -> PublicValuesSolidity {
    PublicValuesSolidity {
        report: ReportSolidity {
            slot: conversions::u64_to_uint256(report.slot),
            deposited_lido_validators: conversions::u64_to_uint256(report.deposited_lido_validators),
            exited_lido_validators: conversions::u64_to_uint256(report.exited_lido_validators),
            lido_cl_valance: conversions::u64_to_uint256(report.lido_cl_balance),
        },
        metadata: ReportMetadataSolidity {
            slot: conversions::u64_to_uint256(report.slot),
            epoch: conversions::u64_to_uint256(report.epoch),
            lido_withdrawal_credentials: report.lido_withdrawal_credentials.to_fixed_bytes().into(),
            beacon_block_hash: beacon_block_hash.to_fixed_bytes().into(),
            state_for_previous_report: LidoValidatorStateSolidity {
                slot: conversions::u64_to_uint256(old_state_slot),
                merkle_root: old_state_hash.to_fixed_bytes().into(),
            },
            new_state: LidoValidatorStateSolidity {
                slot: conversions::u64_to_uint256(new_state_slot),
                merkle_root: new_state_hash.to_fixed_bytes().into(),
            },
        },
    }
}
