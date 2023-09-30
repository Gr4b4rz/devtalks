use pyo3::prelude::*;
pub mod complex_functions;
use complex_functions::{
    estimate_pi, get_filtered_pkt_infos, get_filtered_pkt_infos2, get_pkt_infos, PktFilter, PktInfo,
};

#[pyfunction(name = "estimate_pi")]
fn py_estimate_pi(py: Python<'_>, n: i32) -> PyResult<f64> {
    py.allow_threads(move || Ok(estimate_pi(n)))
}

#[pyfunction(name = "get_pkt_infos")]
fn py_get_pkt_infos(py: Python<'_>, filename: &str) -> PyResult<Vec<PktInfo>> {
    py.allow_threads(move || Ok(get_pkt_infos(filename)))
}

#[pyfunction(name = "get_filtered_pkt_infos")]
fn py_get_filtered_pkt_infos(
    _py: Python<'_>,
    filename: &str,
    pkt_filter: &PyAny,
) -> PyResult<Vec<PktInfo>> {
    Ok(get_filtered_pkt_infos(filename, pkt_filter))
}

#[pyfunction(name = "get_filtered_pkt_infos2")]
fn py_get_filtered_pkt_infos2(
    py: Python<'_>,
    filename: &str,
    pkt_filter: &PyAny,
) -> PyResult<Vec<PktInfo>> {
    let rust_pkt_filter: PktFilter = pkt_filter.extract().unwrap();
    py.allow_threads(move || Ok(get_filtered_pkt_infos2(filename, &rust_pkt_filter)))
}

#[pymodule]
fn pyrust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PktInfo>()?;
    m.add_function(wrap_pyfunction!(py_estimate_pi, m)?)?;
    m.add_function(wrap_pyfunction!(py_get_pkt_infos, m)?)?;
    m.add_function(wrap_pyfunction!(py_get_filtered_pkt_infos, m)?)?;
    m.add_function(wrap_pyfunction!(py_get_filtered_pkt_infos2, m)?)?;
    Ok(())
}
