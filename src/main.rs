use clap::Parser;
use std::io::stdout;
use std::io::{self, Write};
use std::sync::Arc;

use fault_simulator::config::{Args, Config};
use fault_simulator::error::SimulatorError;
use fault_simulator::prelude::*;

mod compile;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

// Fault Injection Simulator for ARM Cortex-M Processors
//
// This is the main entry point for the fault injection simulator targeting
// ARMv8-M processors (e.g., Cortex-M33). The simulator provides comprehensive
// fault injection capabilities for security research and vulnerability assessment.
//
// Key Features:
// * Multi-threaded Execution: Parallel fault injection for performance
// * Multiple Attack Types: Glitch, register corruption, instruction modification
// * Configurable Campaigns: JSON configuration and command-line control
// * Debug Integration: Source-level fault correlation and analysis
// * Comprehensive Reporting: Detailed attack success analysis
//
// Supported Fault Types:
// * Glitch Attacks: Clock/voltage glitching causing instruction skipping
// * Register Bit Flips: Single-bit errors in processor registers
// * Register Flooding: Complete register corruption attacks
// * Command Bit Flips: Instruction stream corruption
//
// Attack Classes:
// * all - Test all available fault types systematically
// * single - Single fault injection per execution
// * double - Two-fault combination attacks
// * Specific types: glitch, regbf, regfld, cmdbf
//
// Configuration Options:
// The simulator accepts both command-line arguments and JSON configuration
// files, with command-line parameters taking precedence for flexible usage
// in automated testing environments.

/// Main entry point for the fault injection simulator.
///
/// Orchestrates the complete fault injection simulation workflow including:
/// * Configuration loading and validation
/// * Target program compilation (if needed)
/// * ELF file loading and analysis
/// * Multi-threaded simulation setup
/// * Fault injection campaign execution
/// * Results analysis and reporting
///
/// # Configuration Hierarchy
///
/// 1. **Default values**: Sensible defaults for all parameters
/// 2. **JSON configuration**: Structured configuration from file
/// 3. **Command-line overrides**: CLI arguments override file settings
///
/// # Error Handling
///
/// Returns descriptive error messages for:
/// * Configuration parsing failures
/// * ELF file loading errors
/// * Thread initialization problems
/// * Simulation execution failures
///
/// # Performance Considerations
///
/// * Automatically determines optimal thread count
/// * Balances fault attack threads with general simulation threads
/// * Provides progress reporting for long-running campaigns
///
/// # Returns
///
/// * `Ok(())` - Simulation completed successfully
/// * `Err(String)` - Detailed error message describing the failure
fn main() -> Result<(), SimulatorError> {
    // Get parameter from command line
    let args = Args::parse();

    println!("--- Fault injection simulator: {GIT_VERSION} ---\n");

    // Load configuration
    let config = match &args.config {
        Some(config_path) => {
            println!("Loading configuration from: {}", config_path.display());
            let mut config = Config::from_file(config_path)?;
            config.override_with_args(&args);
            config
        }
        None => Config::from_args(&args),
    };

    // Initialize logger with level from config (or use RUST_LOG env var if set)
    if std::env::var("RUST_LOG").is_err() {
        let log_level = match config.log_level.as_str() {
            "off" => "off",
            "error" => "error",
            "warn" => "warn",
            "info" => "info",
            "debug" => "debug",
            "trace" => "trace",
            _ => "off", // default
        };
        std::env::set_var("RUST_LOG", log_level);
    }
    env_logger::init();

    // Check for compilation flag and provided elf file
    let path = match config.elf {
        None => {
            // Compilation according cli parameter
            if !config.no_compilation {
                compile::compile();
            }
            std::path::PathBuf::from("content/bin/aarch32/victim.elf")
        }
        Some(elf_path) => {
            println!("Provided elf file: {}\n", elf_path.display());
            elf_path
        }
    };

    // Log initial register context if provided
    if !config.initial_registers.is_empty() {
        log::info!("Using custom initial register context:");
        for (reg, value) in &config.initial_registers {
            log::info!("  {:?}: 0x{:08X}", reg, value);
        }
    }

    // Log code patches if provided
    if !config.code_patches.is_empty() {
        log::info!("Code patches configured: {}", config.code_patches.len());
    }

    // Log memory regions if provided
    if !config.memory_regions.is_empty() {
        log::info!(
            "Custom memory regions configured: {}",
            config.memory_regions.len()
        );
    }

    // Load victim data
    let mut file_data: ElfFile = ElfFile::new(path)?;

    // Apply patches immediately after loading
    if !config.code_patches.is_empty() {
        file_data.apply_patches(&config.code_patches)?;
    }
    // Create simulation configuration
    let sim_config = SimulationConfig::new(
        config.max_instructions,
        config.deep_analysis,
        config.success_addresses,
        config.failure_addresses,
        config.initial_registers,
        config.memory_regions,
        config.log_level.clone(),
        config.result_checks,
    );
    // Create user thread for simulation
    let user_thread = Arc::new(SimulationThread::new_with_threads(
        sim_config,
        &file_data,
        config.threads,
    )?);

    // Load victim data for attack simulation with dedicated fault attack threads
    // Use half the available threads for fault attacks to balance with general simulation
    let mut attack_sim =
        FaultAttacks::new_with_threads(&file_data, Arc::clone(&user_thread), config.threads)?;
    // Check for correct program behavior
    if !config.no_check {
        println!("Check for correct program behavior:");
        attack_sim.check_for_correct_behavior()?;
    }

    // Check if trace is selected
    if config.trace {
        attack_sim.print_trace()?;
        return Ok(());
    }

    println!("\nRun fault simulations:");

    // Run attack simulation
    if config.faults.is_empty() {
        let class = config.class.clone();
        let subclass = if class.len() > 1 { &class[1..] } else { &[] };
        match class.first().map(|s| s.as_str()) {
            Some("all") | None => {
                if !attack_sim.single(subclass, config.run_through)?.0 {
                    attack_sim.double(subclass, config.run_through)?;
                }
            }
            Some("single") => {
                attack_sim.single(subclass, config.run_through)?;
            }
            Some("double") => {
                attack_sim.double(subclass, config.run_through)?;
            }
            _ => println!("Unknown attack class!"),
        }
    } else {
        // Get fault type and numbers
        let faults: Vec<Vec<FaultType>> = config
            .faults
            .iter()
            .filter_map(|argument| match get_fault_from(argument) {
                Ok(val) => Some(vec![val]),
                Err(_) => None,
            })
            .collect();

        // Use threaded fault simulation for better performance
        // Falls back to regular simulation if threads aren't available
        let _result = attack_sim.fault_simulation(&faults)?;
    }

    // Pretty print fault data
    attack_sim.print_fault_data();

    println!("Overall tests executed {}", attack_sim.count_sum);

    if config.analysis {
        loop {
            {
                if attack_sim.fault_data.is_empty() {
                    println!("No successful attacks!");
                    break;
                }
                print!("\nList trace for attack number : (Return for exit): ");
                stdout().flush().unwrap();
                let mut buffer = String::new();
                if io::stdin().read_line(&mut buffer).is_ok() {
                    if let Ok(number) = buffer.trim().parse::<usize>() {
                        attack_sim.print_trace_for_fault(number)?;
                        continue;
                    }
                }
                break;
            }
        }
    }
    Ok(())
}
