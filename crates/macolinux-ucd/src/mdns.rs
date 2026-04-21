use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const CLASS_IN: u16 = 0x0001;
const CLASS_IN_FLUSH: u16 = 0x8001;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const TYPE_ANY: u16 = 255;

#[derive(Debug, Clone)]
pub struct MdnsAdvert {
    pub service_type: String,
    pub instance: String,
    pub hostname: String,
    pub port: u16,
    pub ipv4: Ipv4Addr,
    pub multicast_ipv4: Ipv4Addr,
    pub txt: Vec<String>,
}

impl MdnsAdvert {
    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        let socket = bind_mdns_socket(self.multicast_ipv4)?;
        self.announce(&socket)?;

        let mut buf = [0u8; 9000];
        loop {
            let (len, src) = socket.recv_from(&mut buf)?;
            let questions = match parse_questions(&buf[..len]) {
                Ok(questions) => questions,
                Err(err) => {
                    eprintln!("mDNS: ignoring malformed query from {src}: {err}");
                    continue;
                }
            };

            if questions
                .iter()
                .any(|question| self.should_answer(question))
            {
                let response = self.response_packet()?;
                socket.send_to(&response, SocketAddrV4::new(MDNS_ADDR, MDNS_PORT))?;
            }
        }
    }

    pub fn announce(&self, socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
        let response = self.response_packet()?;
        socket.send_to(&response, SocketAddrV4::new(MDNS_ADDR, MDNS_PORT))?;
        Ok(())
    }

    fn should_answer(&self, question: &Question) -> bool {
        let service = canonical_name(&self.service_type);
        let instance = canonical_name(&self.instance_name());
        let hostname = canonical_name(&self.hostname);

        match question.qtype {
            TYPE_ANY => {
                question.name == service || question.name == instance || question.name == hostname
            }
            TYPE_PTR => question.name == service,
            TYPE_SRV | TYPE_TXT => question.name == instance,
            TYPE_A => question.name == hostname,
            _ => false,
        }
    }

    fn response_packet(&self) -> Result<Vec<u8>, MdnsError> {
        let mut out = Vec::new();
        write_u16(&mut out, 0);
        write_u16(&mut out, 0x8400);
        write_u16(&mut out, 0);
        write_u16(&mut out, 4);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);

        let instance = self.instance_name();
        write_ptr_record(&mut out, &self.service_type, &instance)?;
        write_srv_record(&mut out, &instance, self.port, &self.hostname)?;
        write_txt_record(&mut out, &instance, &self.txt)?;
        write_a_record(&mut out, &self.hostname, self.ipv4)?;
        Ok(out)
    }

    fn instance_name(&self) -> String {
        format!(
            "{}.{}",
            self.instance.trim_end_matches('.'),
            self.service_type
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    name: String,
    qtype: u16,
}

fn bind_mdns_socket(interface: Ipv4Addr) -> Result<UdpSocket, Box<dyn Error>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        MDNS_PORT,
    )))?;
    socket.join_multicast_v4(&MDNS_ADDR, &interface)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_ttl_v4(255)?;
    Ok(socket.into())
}

fn parse_questions(packet: &[u8]) -> Result<Vec<Question>, MdnsError> {
    if packet.len() < 12 {
        return Err(MdnsError("DNS packet too short".into()));
    }
    let qdcount = read_u16(packet, 4)? as usize;
    let mut offset = 12;
    let mut out = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let name = read_name(packet, &mut offset, 0)?;
        if offset + 4 > packet.len() {
            return Err(MdnsError("DNS question truncated".into()));
        }
        let qtype = read_u16(packet, offset)?;
        offset += 4;
        out.push(Question {
            name: canonical_name(&name),
            qtype,
        });
    }
    Ok(out)
}

fn read_name(packet: &[u8], offset: &mut usize, depth: usize) -> Result<String, MdnsError> {
    if depth > 16 {
        return Err(MdnsError("DNS name compression loop".into()));
    }

    let mut labels = Vec::new();
    loop {
        if *offset >= packet.len() {
            return Err(MdnsError("DNS name truncated".into()));
        }
        let len = packet[*offset];
        *offset += 1;

        if len & 0xc0 == 0xc0 {
            if *offset >= packet.len() {
                return Err(MdnsError("DNS compression pointer truncated".into()));
            }
            let pointer = (((len & 0x3f) as usize) << 8) | packet[*offset] as usize;
            *offset += 1;
            let mut pointer_offset = pointer;
            labels.push(read_name(packet, &mut pointer_offset, depth + 1)?);
            break;
        }

        if len == 0 {
            break;
        }

        let end = *offset + len as usize;
        if end > packet.len() {
            return Err(MdnsError("DNS label truncated".into()));
        }
        let label = std::str::from_utf8(&packet[*offset..end])
            .map_err(|_| MdnsError("DNS label is not UTF-8".into()))?;
        labels.push(label.to_string());
        *offset = end;
    }
    Ok(labels.join("."))
}

fn write_ptr_record(out: &mut Vec<u8>, service: &str, instance: &str) -> Result<(), MdnsError> {
    write_name(out, service)?;
    write_u16(out, TYPE_PTR);
    write_u16(out, CLASS_IN);
    write_u32(out, 120);
    let mut rdata = Vec::new();
    write_name(&mut rdata, instance)?;
    write_len_prefixed(out, &rdata)?;
    Ok(())
}

fn write_srv_record(
    out: &mut Vec<u8>,
    instance: &str,
    port: u16,
    hostname: &str,
) -> Result<(), MdnsError> {
    write_name(out, instance)?;
    write_u16(out, TYPE_SRV);
    write_u16(out, CLASS_IN_FLUSH);
    write_u32(out, 120);
    let mut rdata = Vec::new();
    write_u16(&mut rdata, 0);
    write_u16(&mut rdata, 0);
    write_u16(&mut rdata, port);
    write_name(&mut rdata, hostname)?;
    write_len_prefixed(out, &rdata)?;
    Ok(())
}

fn write_txt_record(out: &mut Vec<u8>, instance: &str, txt: &[String]) -> Result<(), MdnsError> {
    write_name(out, instance)?;
    write_u16(out, TYPE_TXT);
    write_u16(out, CLASS_IN_FLUSH);
    write_u32(out, 120);

    let mut rdata = Vec::new();
    for item in txt {
        if item.len() > 255 {
            return Err(MdnsError(format!("TXT item too long: {item:?}")));
        }
        rdata.push(item.len() as u8);
        rdata.extend_from_slice(item.as_bytes());
    }
    write_len_prefixed(out, &rdata)?;
    Ok(())
}

fn write_a_record(out: &mut Vec<u8>, hostname: &str, addr: Ipv4Addr) -> Result<(), MdnsError> {
    write_name(out, hostname)?;
    write_u16(out, TYPE_A);
    write_u16(out, CLASS_IN_FLUSH);
    write_u32(out, 120);
    write_len_prefixed(out, &addr.octets())?;
    Ok(())
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), MdnsError> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(MdnsError(format!("invalid DNS label in {name:?}")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn write_len_prefixed(out: &mut Vec<u8>, rdata: &[u8]) -> Result<(), MdnsError> {
    if rdata.len() > u16::MAX as usize {
        return Err(MdnsError("DNS RDATA too large".into()));
    }
    write_u16(out, rdata.len() as u16);
    out.extend_from_slice(rdata);
    Ok(())
}

fn canonical_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, MdnsError> {
    if offset + 2 > packet.len() {
        return Err(MdnsError("u16 truncated".into()));
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsError(String);

impl fmt::Display for MdnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for MdnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_contains_expected_records() {
        let advert = MdnsAdvert {
            service_type: "_companion-link._tcp.local".into(),
            instance: "linux-peer".into(),
            hostname: "linux-peer.local".into(),
            port: 49152,
            ipv4: Ipv4Addr::new(192, 0, 2, 11),
            multicast_ipv4: Ipv4Addr::UNSPECIFIED,
            txt: vec!["rpFl=0x20000".into(), "rpVr=715.2".into()],
        };

        let packet = advert.response_packet().unwrap();
        assert_eq!(read_u16(&packet, 6).unwrap(), 4);
        assert!(packet
            .windows(b"_companion-link".len())
            .any(|window| window == b"_companion-link"));
        assert!(packet
            .windows(b"rpFl=0x20000".len())
            .any(|w| w == b"rpFl=0x20000"));
        assert!(packet
            .windows([192, 0, 2, 11].len())
            .any(|w| w == [192, 0, 2, 11]));
    }

    #[test]
    fn parses_ptr_question() {
        let mut packet = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        write_name(&mut packet, "_companion-link._tcp.local").unwrap();
        write_u16(&mut packet, TYPE_PTR);
        write_u16(&mut packet, CLASS_IN);

        let questions = parse_questions(&packet).unwrap();
        assert_eq!(
            questions,
            vec![Question {
                name: "_companion-link._tcp.local".into(),
                qtype: TYPE_PTR
            }]
        );
    }
}
