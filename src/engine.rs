use pyo3::prelude::*;
use pyo3::types::PyModule;
use log::{info, error}; 
use std::env;

pub struct PythonWafBridge {
   
    waf_instance: Py<PyAny>,
}

impl PythonWafBridge {
    pub fn new() -> Self {
        info!("Initializing Python WAF Bridge...");

        let instance = Python::with_gil(|py| {
            
            let sys = py.import("sys").expect("Failed to import sys");
            let paths = sys.getattr("path").expect("Failed to get path");
            let current_dir = env::current_dir().expect("Failed to get current dir");
            
            paths.call_method1("append", (current_dir.to_str().unwrap(),)).unwrap();

            
            let module = PyModule::import(py, "waf_brain.core")
                .expect("CRITICAL: Could not load waf_brain.core. Check file structure.");

            
            let waf_class = module.getattr("WafEngine").expect("Could not find WafEngine class");
            let instance = waf_class.call0().expect("Failed to initialize WAF AI Model");
            
            info!("Python AI Model loaded into memory successfully.");
            
            
            instance.unbind()
        });

        Self {
            waf_instance: instance,
        }
    }

    pub fn analyze(&self, method: &str, uri: &str, headers: &str, body: &str) -> f64 {
        Python::with_gil(|py| {
            
            let args = (method, uri, headers, body);
            
            
            match self.waf_instance.bind(py).call_method1("inspect_request", args) {
                Ok(result) => {
                    
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
