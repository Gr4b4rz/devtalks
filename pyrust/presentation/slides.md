---
theme: apple-basic
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Slidev Starter Template
  Presentation slides for developers.

  Learn more at [Sli.dev](https://sli.dev)
drawings:
  persist: false
transition: slide-left
title: Rust in Python
#background: "crab_and_snake.jpeg"
layout: intro
---

# Rust in Python

### Speeding up Python code with maturin and pyo3

<div class="abs-br m-12" style="text-align: left; color: white;">
    Piotr Grabarski<br>
    https://github.com/Gr4b4rz
</div>

<!--
The last comment block of each slide will be treated as slide notes. It will be visible and editable in Presenter Mode along with the slide. [Read more in the docs](https://sli.dev/guide/syntax.html#notes)
-->

---
transition: fade-out
---

# Why not Python?

Python is an interpreted, high-level, general-purpose programming language. It is dynamically typed and garbage-collected ~Wikipedia

<span v-click>🐌 Its slow</span>
<p v-click>🐌 Hard to do things in paralell because of GIL - only one thread hold the control of the Python interpreter</p>

<p v-click>How we usually overcome this?</p>
<p v-click>🚀 By importing already compiled functions and classes</p>
<p v-click>🚀 By forking - running code on workers</p>
<arrow v-click x1="650" y1="360" x2="500" y2="290" color="#564" width="3" arrowSize="1" />
---
layout: two-cols
---

# π estimation in Python
```py
def estimate_pi(n: int) -> float:
    """
    Estimate pi using Leibniz’s formula:
    X = 4 - 4/3 + 4/5 - 4/7 + 4/9 ...
    """
    denominator = 1
    pi = 0
    sign = 1

    for _ in range(n):
        pi += sign * 4/denominator
        denominator += 2
        sign = -sign

    return pi
```

::right::

# π estimation in Rust
```rs
/// Estimate pi using Leibniz’s formula:
/// X = 4 - 4/3 + 4/5 - 4/7 + 4/9 ...
pub fn estimate_pi(n: i32) -> f64 {
    let mut denominator = 1.0;
    let mut pi = 0.0;
    let mut sign = 1.0;

    for _ in 0..n {
        pi += sign * 4.0 / denominator;
        denominator += 2.0;
        sign = -sign;
    }

    pi
}
```

<style>
.footnotes-sep {
  @apply mt-20 opacity-10;
}
.footnotes {
  @apply text-sm opacity-75;
}
.footnote-backref {
  display: none;
}
</style>

---
title: Execution time comparison
level: 2
---
# Execution time comparison

#### python3 main.py --pi 100000000 --py

<v-click>
```console {all|4}
Running π estimation in python
estimated: π=3.141592643589
target:    π=3.141592653589
Estimation took 8.95 seconds
```
</v-click>

<p v-click> python3 main.py --pi 100000000 --rust </p>
<v-click>
```console {all|4}
Running π estimation in rust
estimated: π=3.141592643589
target:    π=3.141592653589
Estimation took 0.15 seconds
```
</v-click>

---
class: px-20
---

# Pyo3 and maturin

* Pyo3 [https://pyo3.rs/v0.19.1](https://pyo3.rs/v0.19.1)
* Maturin [https://pypi.org/project/maturin](https://pypi.org/project/maturin)

## Lets dig into the code ...

---
level: 2
---

# Packet decoding in Python

```rs
/// Decode packets from given pcap file.
/// Store each packet data in PktInfo struct
/// Return list of PktInfo structs
```

#### python3 main.py --pcap-info some_pcap.pcap --py

<v-click>
```console {all|3}
Decoding packets in python
Decoded pcaps: 100000
Pcap decoding took 29.87 seconds
```
</v-click>

<p v-click> python3 main.py --pcap-info some_pcap.pcap --rust </p>
<v-click>
```console {all|3}
Decoding packets in rust
Decoded pcaps: 100000
Pcap decoding took 0.04 seconds
```
</v-click>

<style>
h1 {
  font-size: 5em;
}
</style>

---

# Using Rust structs in Python

* Getting fields
```rs
#[pyo3(get, set)]
pub src_port: u16,
```
```rs
#[getter(src_ip)]
fn src_ip(&self) -> pyo3::PyResult<String> {
    Ok(self.src_ip.to_string())
}
```

* Creating new instances
```rs
#[new]
fn new(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Result<Self, AddrParseError> {
    ...
}
```


* Printing
```rs
fn __repr__(&self) -> String {
    ...
}
```

---

# Using Python structs in Rust

* GIL
```rs
pub fn get_filtered_pkt_infos(filename: &str, pkt_filter: &PyAny) -> Vec<PktInfo>
```

* Accessing fields and methods
```rs
fn call_method(&self, name: &str, args: (u16, u16), kwargs: Option<&PyDict>) -> Result<&PyAny, PyErr>
```

* NO (less) GIL
```rs
#[derive(pyo3::FromPyObject)]
pub struct PktFilter {
    #[pyo3(item)]
    pub ports: Vec<u16>,
    #[pyo3(item)]
    pub ips: Vec<String>,
}
```

---
layout: center
class: text-center
---

# Thank you

## <br>
## <br>
### https://pyo3.rs/main
### https://github.com/PyO3/maturin
