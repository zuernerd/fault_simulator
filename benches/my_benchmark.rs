use criterion::{criterion_group, criterion_main, Criterion};
use fault_simulator::prelude::*;
use std::sync::Arc;

fn get_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn criterion_benchmark(c: &mut Criterion) {
    let cpu_cores = get_cpu_cores();
    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    let user_thread = Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],                           // success_addresses
                vec![],                           // failure_addresses
                std::collections::HashMap::new(), // initial_registers
                vec![],                           // memory_regions
                "info".to_string(),               // log_level
                None,                             // result_checks
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    let mut group = c.benchmark_group("fault-attack_peformance");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(50));
    group.sample_size(10);
    group.bench_function("single attack", |b| {
        b.iter(|| {
            let _ = attack.single(&["glitch".to_string()], false);
            let _ = attack.single(&["glitch".to_string()], false);
        })
    });
    group.bench_function("double attack", |b| {
        b.iter(|| {
            let _ = attack.double(&["glitch".to_string()], false);
            let _ = attack.double(&["glitch".to_string()], false);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
