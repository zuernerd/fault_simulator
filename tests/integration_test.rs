use assert_cmd::prelude::*;
use fault_simulator::prelude::*;
use predicates::prelude::*;
use std::process::Command; // Used for writing assertions
use std::sync::Arc;

pub fn get_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[test]
/// Test for single glitch attack api
///
/// This test runs a single glitch atttacks on two different binaries (victim_.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_single_glitch() {
    let cpu_cores = get_cpu_cores();
    // Load victim data
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    // Create user thread for simulation with threads started
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],
                vec![],
                std::collections::HashMap::new(),
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    // Create fault attacks with dedicated threads
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();

    // Result is (success: bool, number_of_attacks: usize)
    let vec = ["glitch".to_string()];
    assert_eq!((true, 35), attack.single(&mut vec.iter(), false).unwrap());

    // Create user thread for simulation with threads started
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],
                vec![],
                std::collections::HashMap::new(),
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    // Create fault attacks with dedicated threads
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();

    // Result is (success: bool, number_of_attacks: usize)
    let vec = ["glitch".to_string()];
    assert_eq!((true, 280), attack.single(&mut vec.iter(), true).unwrap());

    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_4.elf")).unwrap();
    // Create user thread for simulation with threads started
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],
                vec![],
                std::collections::HashMap::new(),
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    // Create fault attacks with dedicated threads
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    assert_eq!((false, 376), attack.single(&mut vec.iter(), true).unwrap());
}

#[test]
/// Test for double glitch attack api
///
/// This test runs a double glitch attacks on two different binaries (victim_3.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_double_glitch() {
    let cpu_cores = get_cpu_cores();
    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],                           // success_addresses
                vec![],                           // failure_addresses
                std::collections::HashMap::new(), // initial_registers
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );

    // TODO: fix inconsistence of results  != 22808
    let mut attack =
        FaultAttacks::new_with_threads(&file_data, user_thread.clone(), cpu_cores).unwrap();
    // Result is (false: bool, number_of_attacks: usize)
    let vec = ["glitch".to_string()];
    assert_eq!(
        (false, 22808),
        attack.double(&mut vec.iter(), false).unwrap()
    );

    // Test second scenario with regbf
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();

    // Result is (success: bool, number_of_attacks: usize)
    let vec = ["regbf".to_string()];
    assert_eq!((true, 6916), attack.double(&mut vec.iter(), false).unwrap());
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on two different binaries (victim_.elf, victim_3.elf)
/// and checks if the correct faults are found, identified by their addresses
fn run_fault_simulation_one_glitch() {
    let cpu_cores = get_cpu_cores();
    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],                           // success_addresses
                vec![],                           // failure_addresses
                std::collections::HashMap::new(), // initial_registers
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Result is bool indicating success of fault simulation
    let result = attack.fault_simulation(&[vec![Glitch::new(1)]]).unwrap();
    let result_data = attack.get_fault_data();

    assert_eq!(true, result);
    // Check if correct faults are found (at: 0x80004BA, 0x8000634, 0x800063C)
    assert_eq!(3, result_data.len());
    // Check for correct faults
    assert!(result_data
        .iter()
        .any(|fault_data| match fault_data[0].record {
            TraceRecord::Fault { address, .. } => address == 0x80004BA,
            _ => false,
        }));
    assert!(result_data
        .iter()
        .any(|fault_data| match fault_data[0].record {
            TraceRecord::Fault { address, .. } => address == 0x8000634,
            _ => false,
        }));
    assert!(result_data
        .iter()
        .any(|fault_data| match fault_data[0].record {
            TraceRecord::Fault { address, .. } => address == 0x800063C,
            _ => false,
        }));
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on victim_3.elf
/// and checks if the correct faults are found, identified by their addresses
fn run_fault_simulation_two_glitches() {
    let cpu_cores = get_cpu_cores();
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let mut user_thread = SimulationThread::with_params(
        2000,
        false,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
    )
    .unwrap();
    user_thread
        .start_worker_threads(&file_data, cpu_cores)
        .unwrap();
    let mut attack = FaultAttacks::new(file_data.clone(), Arc::new(user_thread)).unwrap();
    attack.start_fault_attack_threads(cpu_cores).unwrap();

    let result = attack
        .fault_simulation(&[vec![Glitch::new(1), Glitch::new(10)]])
        .unwrap();

    assert_eq!(true, result);
    let result_data = attack.get_fault_data();

    println!("Result: {:?}", result);
    // Check if correct faults are found (at: 0x8000676, 0x80006a8)
    assert_eq!(1, result_data.len());
    // Check for correct faults
    assert!(result_data[0]
        .iter()
        .any(|fault_data| match fault_data.record {
            TraceRecord::Fault { address, .. } => address == 0x8000676,
            _ => false,
        }));
    println!("Fault data: {:?}", result_data);
    assert!(result_data[0]
        .iter()
        .any(|fault_data| match fault_data.record {
            TraceRecord::Fault { address, .. } => address == 0x80006a4,
            _ => false,
        }));
}

#[test]
/// Test for success_addresses and failure_addresses functionality
///
/// This test runs fault simulation on victim_3.elf with custom success and failure addresses
/// Success address: 0x08000490, Failure addresses: 0x08000690, 0x08000014
fn test_success_and_failure_addresses() {
    let cpu_cores = get_cpu_cores();
    // Define custom success and failure addresses for victim_3.elf
    let success_addresses = vec![0x08000490];
    let failure_addresses = vec![0x08000690, 0x08000014];

    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                success_addresses,
                failure_addresses,
                std::collections::HashMap::new(), // initial_registers
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Test single glitch attack with custom addresses
    let vec = ["glitch".to_string()];
    let single_result = attack.single(&mut vec.iter(), false).unwrap();

    // Verify that the attack runs and produces results
    println!(
        "Single attack result: success={}, attacks={}",
        single_result.0, single_result.1
    );
    assert!(
        single_result.1 > 0,
        "Expected some attack iterations with custom addresses"
    );

    // Test fault simulation with custom addresses
    let _ = attack.fault_simulation(&[vec![Glitch::new(1)]]).unwrap();
    let fault_data = attack.get_fault_data();
    println!(
        "Fault simulation found {} successful attacks",
        fault_data.len()
    );
}

#[test]
/// Integration test for JSON config loading
///
/// This test creates a temporary JSON config file, runs the simulator with
/// --config, and checks that the output contains expected values.
/// It verifies that the config file is correctly parsed and used.
fn test_json_config() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args(["--config", "tests/test_config.json"])
        .output()
        .expect("Failed to run binary");

    cmd.assert()
        .stdout(predicate::str::contains("Fault injection simulator"))
        .stdout(predicate::str::contains("glitch"))
        .success();
}

#[test]
/// Test for initial register context functionality
///
/// This test verifies that custom initial register values can be applied
/// and the fault simulation runs without errors using meaningful ARM register values
fn test_initial_register_context() {
    use std::collections::HashMap;
    use unicorn_engine::RegisterARM;

    let cpu_cores = get_cpu_cores();
    // Create initial register context with meaningful ARM values
    let mut initial_registers = HashMap::new();
    initial_registers.insert(RegisterARM::R7, 0x2000FFF8); // Frame pointer
    initial_registers.insert(RegisterARM::SP, 0x2000FFF8); // Stack pointer
    initial_registers.insert(RegisterARM::LR, 0x08000005); // Link register
    initial_registers.insert(RegisterARM::PC, 0x8000620); // Program counter

    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![], // success_addresses
                vec![], // failure_addresses
                initial_registers,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Test that fault simulation works with custom registers
    let _ = attack.fault_simulation(&[vec![Glitch::new(1)]]).unwrap();
    let result_data = attack.get_fault_data();
    // Should complete without errors (specific results may vary)
    println!(
        "Fault simulation with custom registers: {} attacks found",
        result_data.len()
    );
}

#[test]
/// Test JSON config with initial registers
///
/// This test verifies that initial register configuration is loaded from JSON
/// and displayed in the output
fn test_json_config_initial_registers() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--config",
        "tests/test_config.json",
        "--no-check",
        "--max-instructions",
        "100",
    ]);

    cmd.assert()
        .stdout(predicate::str::contains(
            "Using custom initial register context:",
        ))
        .stdout(predicate::str::contains("R7: 0x2000FFF8"))
        .stdout(predicate::str::contains("SP: 0x2000FFF8"))
        .stdout(predicate::str::contains("LR: 0x08000005"))
        .stdout(predicate::str::contains("PC: 0x08000620"))
        .success();
}
