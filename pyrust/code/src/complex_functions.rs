use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pyo3::types::PyBool;
use pyo3::{pyclass, pymethods, PyAny};
use std::net::{AddrParseError, IpAddr};

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

#[pyclass]
pub struct PktInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    #[pyo3(get, set)]
    pub src_port: u16,
    #[pyo3(get, set)]
    pub dst_port: u16,
}

#[pymethods]
impl PktInfo {
    #[getter(src_ip)]
    fn src_ip(&self) -> pyo3::PyResult<String> {
        Ok(self.src_ip.to_string())
    }

    #[new]
    fn new(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Self, AddrParseError> {
        let src_ip = src_ip.parse()?;
        let dst_ip = dst_ip.parse()?;
        Ok(PktInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "<PktInfo src_ip={:?} dst_ip={:?} scr_port={:?} dst_port={:?}>",
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
        )
    }
}

/// Decode packets from given pcap file.
/// Store each packet IP/port data in PktInfo struct
/// Return list of PktInfo structs
pub fn get_pkt_infos(filename: &str) -> Vec<PktInfo> {
    let mut pkt_infos: Vec<PktInfo> = Vec::new();
    let mut cap = pcap::Capture::from_file(filename).unwrap();
    while let Ok(pkt) = cap.next_packet() {
        let eth_pkt = EthernetPacket::new(pkt.data).unwrap();
        if eth_pkt.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let ip_pkt = Ipv4Packet::new(eth_pkt.payload()).unwrap();
        if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }
        let tcp_packet = TcpPacket::new(ip_pkt.payload()).unwrap();
        let pkt_info = PktInfo {
            src_ip: std::net::IpAddr::V4(ip_pkt.get_source()),
            dst_ip: std::net::IpAddr::V4(ip_pkt.get_destination()),
            src_port: tcp_packet.get_source(),
            dst_port: tcp_packet.get_destination(),
        };
        pkt_infos.push(pkt_info);
    }
    pkt_infos
}

/// The same as get_pkt_infos but with packet filtering
pub fn get_filtered_pkt_infos(filename: &str, pkt_filter: &PyAny) -> Vec<PktInfo> {
    let mut pkt_infos: Vec<PktInfo> = Vec::new();
    let mut cap = pcap::Capture::from_file(filename).unwrap();
    while let Ok(pkt) = cap.next_packet() {
        let eth_pkt = EthernetPacket::new(pkt.data).unwrap();
        if eth_pkt.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let ip_pkt = Ipv4Packet::new(eth_pkt.payload()).unwrap();
        if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }
        let tcp_packet = TcpPacket::new(ip_pkt.payload()).unwrap();
        let pkt_info = PktInfo {
            src_ip: std::net::IpAddr::V4(ip_pkt.get_source()),
            dst_ip: std::net::IpAddr::V4(ip_pkt.get_destination()),
            src_port: tcp_packet.get_source(),
            dst_port: tcp_packet.get_destination(),
        };

        let res = pkt_filter
            .call_method("check_ports", (pkt_info.src_port, pkt_info.dst_port), None)
            .unwrap()
            .downcast::<PyBool>()
            .unwrap();

        if res.is_true() {
            pkt_infos.push(pkt_info);
        }
        let _filter_src_port = pkt_filter
            .call_method("__getattribute__", ("ports",), None)
            .unwrap();
    }
    pkt_infos
}

#[derive(pyo3::FromPyObject)]
pub struct PktFilter {
    #[pyo3(item)]
    pub ports: Vec<u16>,
    #[pyo3(item)]
    pub ips: Vec<String>,
}

impl PktFilter {
    fn check_ports(&self, src_port: u16, dst_port: u16) -> bool {
        return self.ports.contains(&src_port) || self.ports.contains(&dst_port);
    }
}

/// The same as get_filtered_pkt_infos but without GIL
pub fn get_filtered_pkt_infos2(filename: &str, pkt_filter: &PktFilter) -> Vec<PktInfo> {
    let mut pkt_infos: Vec<PktInfo> = Vec::new();
    let mut cap = pcap::Capture::from_file(filename).unwrap();
    while let Ok(pkt) = cap.next_packet() {
        let eth_pkt = EthernetPacket::new(pkt.data).unwrap();
        if eth_pkt.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let ip_pkt = Ipv4Packet::new(eth_pkt.payload()).unwrap();
        if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }
        let tcp_packet = TcpPacket::new(ip_pkt.payload()).unwrap();
        let pkt_info = PktInfo {
            src_ip: std::net::IpAddr::V4(ip_pkt.get_source()),
            dst_ip: std::net::IpAddr::V4(ip_pkt.get_destination()),
            src_port: tcp_packet.get_source(),
            dst_port: tcp_packet.get_destination(),
        };
        if pkt_filter.check_ports(pkt_info.src_port, pkt_info.dst_port) {
            pkt_infos.push(pkt_info);
        }
    }
    pkt_infos
}
