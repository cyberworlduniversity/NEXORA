//! Normalized disassembly records and deterministic control-flow graph construction.
//!
//! This module does not decode machine instructions. It validates and normalizes
//! output supplied by a separately configured, trusted disassembler adapter.
//! Raw artifact bytes are never executed by this module.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstructionRecord {
    pub address: u64,
    pub size: u8,
    pub mnemonic: String,
    #[serde(default)]
    pub operands: String,
    #[serde(default)]
    pub is_branch: bool,
    #[serde(default)]
    pub is_conditional_branch: bool,
    #[serde(default)]
    pub is_call: bool,
    #[serde(default)]
    pub is_return: bool,
    #[serde(default)]
    pub branch_target: Option<u64>,
}

impl InstructionRecord {
    fn validate(&self) -> Result<(), DisassemblyError> {
        if self.size == 0 {
            return Err(DisassemblyError::ZeroInstructionSize {
                address: self.address,
            });
        }
        if self.mnemonic.trim().is_empty() {
            return Err(DisassemblyError::EmptyMnemonic {
                address: self.address,
            });
        }
        if self.is_conditional_branch && !self.is_branch {
            return Err(DisassemblyError::ConditionalWithoutBranch {
                address: self.address,
            });
        }
        if self.branch_target.is_some() && !self.is_branch && !self.is_call {
            return Err(DisassemblyError::UnexpectedTarget {
                address: self.address,
            });
        }
        Ok(())
    }

    pub fn end_address(&self) -> Result<u64, DisassemblyError> {
        self.address
            .checked_add(u64::from(self.size))
            .ok_or(DisassemblyError::AddressOverflow {
                address: self.address,
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_address: u64,
    pub end_address_exclusive: u64,
    pub instruction_addresses: Vec<u64>,
    pub successors: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller_instruction: u64,
    pub target: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub schema_version: u32,
    pub instruction_count: usize,
    pub blocks: Vec<BasicBlock>,
    pub calls: Vec<CallEdge>,
    pub unresolved_branch_targets: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisassemblyError {
    EmptyMnemonic { address: u64 },
    ZeroInstructionSize { address: u64 },
    ConditionalWithoutBranch { address: u64 },
    UnexpectedTarget { address: u64 },
    AddressOverflow { address: u64 },
    DuplicateAddress { address: u64 },
    OverlappingInstructions { first: u64, second: u64 },
    EmptyInput,
}

impl std::fmt::Display for DisassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMnemonic { address } => {
                write!(f, "instruction at {address:#x} has no mnemonic")
            }
            Self::ZeroInstructionSize { address } => {
                write!(f, "instruction at {address:#x} has zero size")
            }
            Self::ConditionalWithoutBranch { address } => write!(
                f,
                "conditional instruction at {address:#x} is not marked as a branch"
            ),
            Self::UnexpectedTarget { address } => write!(
                f,
                "non-control-flow instruction at {address:#x} has a target"
            ),
            Self::AddressOverflow { address } => {
                write!(f, "instruction at {address:#x} overflows the address space")
            }
            Self::DuplicateAddress { address } => {
                write!(f, "duplicate instruction address {address:#x}")
            }
            Self::OverlappingInstructions { first, second } => {
                write!(f, "instructions at {first:#x} and {second:#x} overlap")
            }
            Self::EmptyInput => write!(f, "disassembly input is empty"),
        }
    }
}
impl std::error::Error for DisassemblyError {}

/// Validate adapter output and derive a deterministic basic-block graph.
/// Instructions must describe one non-overlapping address space.
pub fn build_control_flow_graph(
    instructions: &[InstructionRecord],
) -> Result<ControlFlowGraph, DisassemblyError> {
    if instructions.is_empty() {
        return Err(DisassemblyError::EmptyInput);
    }

    let mut ordered = instructions.to_vec();
    ordered.sort_by_key(|instruction| instruction.address);

    let mut previous: Option<&InstructionRecord> = None;
    for instruction in &ordered {
        instruction.validate()?;
        instruction.end_address()?;
        if previous.is_some_and(|item| item.address == instruction.address) {
            return Err(DisassemblyError::DuplicateAddress {
                address: instruction.address,
            });
        }
        if let Some(previous_instruction) = previous {
            if previous_instruction.end_address()? > instruction.address {
                return Err(DisassemblyError::OverlappingInstructions {
                    first: previous_instruction.address,
                    second: instruction.address,
                });
            }
        }
        previous = Some(instruction);
    }

    let mut leaders = BTreeSet::new();
    leaders.insert(ordered[0].address);
    let addresses: BTreeSet<u64> = ordered.iter().map(|item| item.address).collect();

    for (index, instruction) in ordered.iter().enumerate() {
        if let Some(target) = instruction.branch_target {
            if addresses.contains(&target) {
                leaders.insert(target);
            }
        }
        if instruction.is_branch || instruction.is_return {
            if let Some(next) = ordered.get(index + 1) {
                leaders.insert(next.address);
            }
        }
    }

    let mut blocks = Vec::new();
    let mut current = Vec::new();
    for instruction in &ordered {
        if leaders.contains(&instruction.address) && !current.is_empty() {
            blocks.push(current);
            current = Vec::new();
        }
        current.push(instruction);
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    let mut address_to_block = BTreeMap::new();
    for block in &blocks {
        address_to_block.insert(block[0].address, block[0].address);
        for instruction in block {
            address_to_block.insert(instruction.address, block[0].address);
        }
    }

    let mut normalized_blocks = Vec::new();
    let mut calls = Vec::new();
    let mut unresolved = BTreeSet::new();

    for (index, block) in blocks.iter().enumerate() {
        let first = block[0];
        let last = block[block.len() - 1];
        let mut successors = BTreeSet::new();

        for instruction in block {
            if instruction.is_call {
                calls.push(CallEdge {
                    caller_instruction: instruction.address,
                    target: instruction.branch_target,
                });
            }
        }

        if last.is_branch {
            if let Some(target) = last.branch_target {
                if let Some(block_start) = address_to_block.get(&target) {
                    successors.insert(*block_start);
                } else {
                    unresolved.insert(target);
                }
            }
            if last.is_conditional_branch {
                if let Some(next_block) = blocks.get(index + 1) {
                    successors.insert(next_block[0].address);
                }
            }
        } else if !last.is_return {
            if let Some(next_block) = blocks.get(index + 1) {
                successors.insert(next_block[0].address);
            }
        }

        normalized_blocks.push(BasicBlock {
            start_address: first.address,
            end_address_exclusive: last.end_address()?,
            instruction_addresses: block.iter().map(|item| item.address).collect(),
            successors: successors.into_iter().collect(),
        });
    }

    Ok(ControlFlowGraph {
        schema_version: 1,
        instruction_count: ordered.len(),
        blocks: normalized_blocks,
        calls,
        unresolved_branch_targets: unresolved.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instruction(address: u64, size: u8) -> InstructionRecord {
        InstructionRecord {
            address,
            size,
            mnemonic: "nop".into(),
            operands: String::new(),
            is_branch: false,
            is_conditional_branch: false,
            is_call: false,
            is_return: false,
            branch_target: None,
        }
    }

    #[test]
    fn builds_a_block_from_non_overlapping_instructions() {
        let graph =
            build_control_flow_graph(&[instruction(0x1000, 1), instruction(0x1001, 1)]).unwrap();

        assert_eq!(graph.instruction_count, 2);
        assert_eq!(graph.blocks.len(), 1);
        assert_eq!(graph.blocks[0].instruction_addresses, vec![0x1000, 0x1001]);
        assert_eq!(graph.blocks[0].end_address_exclusive, 0x1002);
    }

    #[test]
    fn rejects_overlapping_instruction_ranges() {
        let error = build_control_flow_graph(&[instruction(0x1000, 2), instruction(0x1001, 1)])
            .unwrap_err();

        assert_eq!(
            error,
            DisassemblyError::OverlappingInstructions {
                first: 0x1000,
                second: 0x1001,
            }
        );
    }

    #[test]
    fn rejects_duplicate_instruction_addresses() {
        let error = build_control_flow_graph(&[instruction(0x1000, 1), instruction(0x1000, 1)])
            .unwrap_err();

        assert_eq!(
            error,
            DisassemblyError::DuplicateAddress { address: 0x1000 }
        );
    }
}
