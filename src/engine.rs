use pyo3::prelude::*;
use pyo3::types::PyModule;
use log::{info, error}; // Removed 'debug' (Fixes unused import)
use std::env;

pub struct PythonWafBridge {
    // Thread-safe reference to the Python object
    waf_instance: Py<PyAny>,
}

impl PythonWafBridge {
    pub fn new() -> Self {
        info!("Initializing Python WAF Bridge...");

        let instance = Python::with_gil(|py| {
            // 1. Setup Path
            let sys = py.import("sys").expect("Failed to import sys");
            let paths = sys.getattr("path").expect("Failed to get path");
            let current_dir = env::current_dir().expect("Failed to get current dir");
            
            paths.call_method1("append", (current_dir.to_str().unwrap(),)).unwrap();

            // 2. Import Module
            let module = PyModule::import(py, "waf_brain.core")
                .expect("CRITICAL: Could not load waf_brain.core. Check file structure.");

            // 3. Instantiate Class
            let waf_class = module.getattr("WafEngine").expect("Could not find WafEngine class");
            let instance = waf_class.call0().expect("Failed to initialize WAF AI Model");
            
            info!("Python AI Model loaded into memory successfully.");
            
            // FIX 1: Use .unbind() instead of .into_py(py)
            // In PyO3 0.23+, unbind() detaches the object from the GIL lifetime 
            // so we can store it in our struct.
            instance.unbind()
        });

        Self {
            waf_instance: instance,
        }
    }

    pub fn analyze(&self, method: &str, uri: &str, headers: &str, body: &str) -> f64 {
        Python::with_gil(|py| {
            // FIX 2: Pass a Rust tuple directly. 
            // Do NOT use PyTuple::new(). call_method1 automatically converts 
            // Rust tuples into Python arguments.
            let args = (method, uri, headers, body);
            
            // FIX 3: Use .bind(py) to access the object
            // We must re-bind the persistent object to the current GIL token 
            // to call methods on it.
            match self.waf_instance.bind(py).call_method1("inspect_request", args) {
                Ok(result) => {
                    // Extract the float result
                    result.extract::<f64>().unwrap_or(0.0)
                },
                Err(e) => {
                    error!("AI Inference Failed: {}", e);
                    0.0 
                }
            }
        })
    }
}