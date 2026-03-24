use thiserror::Error;

/// Structured error types for the fault injection simulator.
///
/// This enum covers all error categories that can occur during
/// simulation configuration, ELF parsing, thread management,
/// and fault injection execution.
#[derive(Error, Debug)]
pub enum SimulatorError {
    /// Configuration file read or parse error.
    #[error("Config error: {0}")]
    Config(String),

    /// ELF file parsing or symbol resolution error.
    #[error("ELF error: {0}")]
    Elf(String),

    /// Thread pool initialization or management error.
    #[error("Thread error: {0}")]
    Thread(String),

    /// Channel send/receive failure.
    #[error("Channel error: {0}")]
    Channel(String),

    /// Timeout waiting for worker thread results.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Simulation execution error (e.g. unicorn emulation failure).
    #[error("Simulation error: {0}")]
    Simulation(String),

    /// A worker thread panicked during execution.
    #[error("Thread panic: {0}")]
    ThreadPanic(String),
}

impl From<String> for SimulatorError {
    fn from(s: String) -> Self {
        SimulatorError::Simulation(s)
    }
}
