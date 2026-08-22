//! A no-host WebAssembly JSON transform backend.

use std::fmt;

use serde_json::Value;
use wasmi::{Config, Engine, Linker, Module, Store, TypedFunc};

use crate::{
    verify_sandbox_capabilities, BackendCapabilities, RequestedCapabilities, SandboxCapability,
    UnsatisfiedCapabilities,
};

/// A bounded JSON transform request owned by the backend boundary.
pub struct PureTransformRequest {
    module: Vec<u8>,
    input: Vec<u8>,
    requested: RequestedCapabilities,
}

impl PureTransformRequest {
    /// Maximum accepted module size in bytes.
    pub const MAX_MODULE_BYTES: usize = 1024 * 1024;
    /// Maximum serialized JSON input and output size in bytes.
    pub const MAX_JSON_BYTES: usize = 64 * 1024;

    /// Validates and builds a pure-transform request.
    pub fn new(
        module: impl AsRef<[u8]>,
        input: Value,
        requested: RequestedCapabilities,
    ) -> Result<Self, PureTransformRequestError> {
        let module = module.as_ref();
        if module.len() > Self::MAX_MODULE_BYTES {
            return Err(PureTransformRequestError::ModuleTooLarge);
        }
        let input = serde_json::to_vec(&input)
            .map_err(|_| PureTransformRequestError::JsonSerializationFailed)?;
        if input.len() > Self::MAX_JSON_BYTES {
            return Err(PureTransformRequestError::InputTooLarge);
        }
        Ok(Self {
            module: module.to_vec(),
            input,
            requested,
        })
    }
}

/// A no-host WebAssembly interpreter for bounded JSON transforms.
pub struct PureTransformBackend {
    capabilities: BackendCapabilities,
}

impl PureTransformBackend {
    /// Maximum interpreter fuel available to one transform.
    pub const MAX_FUEL: u64 = 1_000_000;

    /// Creates a backend with no host capabilities.
    pub fn new() -> Self {
        Self {
            capabilities: BackendCapabilities::new(std::iter::empty::<SandboxCapability>()),
        }
    }

    /// Executes a module using the fixed `(ptr, len) -> (ptr, len)` JSON ABI.
    pub fn execute(&self, request: &PureTransformRequest) -> Result<Value, PureTransformError> {
        verify_sandbox_capabilities(&request.requested, &self.capabilities)?;
        if request.module.is_empty() {
            return Err(PureTransformError::MissingModule);
        }

        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let wasm = request.module.as_slice();
        let module = Module::new(&engine, wasm).map_err(|_| PureTransformError::InvalidModule)?;
        if module.imports().next().is_some() {
            return Err(PureTransformError::UnsupportedImports);
        }

        let mut store = Store::new(&engine, ());
        store
            .set_fuel(Self::MAX_FUEL)
            .map_err(|_| PureTransformError::FuelConfigurationFailed)?;
        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|_| PureTransformError::InstantiationFailed)?
            .start(&mut store)
            .map_err(|_| PureTransformError::InstantiationFailed)?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(PureTransformError::MissingMemoryExport)?;
        memory
            .write(&mut store, 0, &request.input)
            .map_err(|_| PureTransformError::MemoryAccessFailed)?;

        let transform: TypedFunc<(i32, i32), (i32, i32)> = instance
            .get_typed_func(&store, "transform")
            .map_err(|_| PureTransformError::InvalidTransformExport)?;
        let input_len =
            i32::try_from(request.input.len()).map_err(|_| PureTransformError::InputTooLarge)?;
        let (pointer, length) = transform
            .call(&mut store, (0, input_len))
            .map_err(|_| PureTransformError::TransformFailed)?;
        if pointer < 0 || length < 0 {
            return Err(PureTransformError::InvalidOutputRange);
        }
        let pointer =
            usize::try_from(pointer).map_err(|_| PureTransformError::InvalidOutputRange)?;
        let length = usize::try_from(length).map_err(|_| PureTransformError::InvalidOutputRange)?;
        if length > PureTransformRequest::MAX_JSON_BYTES {
            return Err(PureTransformError::OutputTooLarge);
        }

        let mut output = vec![0; length];
        memory
            .read(&store, pointer, &mut output)
            .map_err(|_| PureTransformError::MemoryAccessFailed)?;
        serde_json::from_slice(&output).map_err(|_| PureTransformError::InvalidJsonOutput)
    }
}

impl Default for PureTransformBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// A privacy-safe request validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PureTransformRequestError {
    /// The module exceeds the bounded module input size.
    ModuleTooLarge,
    /// The serialized JSON input exceeds the bounded input size.
    InputTooLarge,
    /// The input value could not be serialized as JSON.
    JsonSerializationFailed,
}

impl fmt::Display for PureTransformRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ModuleTooLarge => "pure transform module exceeds the limit",
            Self::InputTooLarge => "pure transform input exceeds the limit",
            Self::JsonSerializationFailed => "pure transform input is not serializable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PureTransformRequestError {}

/// A privacy-safe pure-transform execution failure.
#[derive(Debug)]
pub enum PureTransformError {
    /// Capability preflight rejected the request.
    Capabilities(UnsatisfiedCapabilities),
    /// The module bytes were absent.
    MissingModule,
    /// The module could not be decoded or validated.
    InvalidModule,
    /// The module declares at least one host import.
    UnsupportedImports,
    /// The module could not be instantiated without host definitions.
    InstantiationFailed,
    /// The module did not export the required linear memory.
    MissingMemoryExport,
    /// The module did not export the required transform ABI.
    InvalidTransformExport,
    /// The input could not be copied into guest memory.
    MemoryAccessFailed,
    /// The interpreter fuel budget could not be configured.
    FuelConfigurationFailed,
    /// The transform trapped or exceeded the interpreter boundary.
    TransformFailed,
    /// The transform input exceeded the ABI boundary.
    InputTooLarge,
    /// The transform returned a negative or otherwise invalid range.
    InvalidOutputRange,
    /// The transform returned more output than the JSON boundary permits.
    OutputTooLarge,
    /// The transform returned bytes that are not JSON.
    InvalidJsonOutput,
}

impl From<UnsatisfiedCapabilities> for PureTransformError {
    fn from(error: UnsatisfiedCapabilities) -> Self {
        Self::Capabilities(error)
    }
}

impl fmt::Display for PureTransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capabilities(error) => fmt::Display::fmt(error, formatter),
            Self::MissingModule => formatter.write_str("pure transform module is missing"),
            Self::InvalidModule => formatter.write_str("pure transform module is invalid"),
            Self::UnsupportedImports => {
                formatter.write_str("pure transform module has unsupported imports")
            }
            Self::InstantiationFailed => {
                formatter.write_str("pure transform module could not be instantiated")
            }
            Self::MissingMemoryExport => {
                formatter.write_str("pure transform memory export is missing")
            }
            Self::InvalidTransformExport => {
                formatter.write_str("pure transform export has an invalid ABI")
            }
            Self::MemoryAccessFailed => formatter.write_str("pure transform memory access failed"),
            Self::FuelConfigurationFailed => {
                formatter.write_str("pure transform fuel could not be configured")
            }
            Self::TransformFailed => formatter.write_str("pure transform execution failed"),
            Self::InputTooLarge => formatter.write_str("pure transform input exceeds the limit"),
            Self::InvalidOutputRange => {
                formatter.write_str("pure transform returned an invalid output range")
            }
            Self::OutputTooLarge => formatter.write_str("pure transform output exceeds the limit"),
            Self::InvalidJsonOutput => formatter.write_str("pure transform output is not JSON"),
        }
    }
}

impl std::error::Error for PureTransformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capabilities(error) => Some(error),
            _ => None,
        }
    }
}
