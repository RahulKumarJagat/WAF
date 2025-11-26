use pyo3::prelude::*;
use pyo3::types::PyModule;
use log::{info, error};
use std::env;

pub struct PythonWafBridge {
    module_name: String,
    class_name: String,
}

impl PythonWafBridge {
    pub fn new() -> Self {
        info!("Connecting to Python Interpreter...");
        
        Python::with_gil(|py| {
            let sys = py.import("sys").expect("Failed to import sys");
            let paths = sys.getattr("path").expect("Failed to get path");
            
            let current_dir = env::current_dir().expect("Failed to get current dir");
            let dir_str = current_dir.to_str().expect("Path contains invalid unicode");
            
            paths.call_method1("append", (dir_str,)).expect("Failed to append path");
            
            if let Err(e) = PyModule::import(py, "waf_brain.core") {
                error!("Python could not find 'waf_brain/core.py'");
                error!("Checked in: {}", dir_str);
                error!("Error: {}", e);
                panic!("Stopping WAF: AI Module Missing");
            }
        });

        Self {
            module_name: "waf_brain.core".to_string(),
            class_name: "WafEngine".to_string(),
        }
    }

    pub fn analyze(&self, method: &str, uri: &str, headers: &str, body: &str) -> f64 {
        Python::with_gil(|py| {
            let module = PyModule::import(py, self.module_name.as_str())
                .expect("Failed to load module");
            
            let waf_class = module.getattr(self.class_name.as_str())
                .expect("Failed to get WAF class");
            
            let waf_instance = waf_class.call0().expect("Failed to instantiate WAF");
            let args = (method, uri, headers, body);
            
            match waf_instance.call_method1("inspect_request", args) {
                Ok(result) => result.extract::<f64>().unwrap_or(0.0),
                Err(e) => {
                    error!("Python Execution Error: {}", e);
                    0.0
                }
            }
        })
    }
}