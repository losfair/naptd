use crate::config::*;
use tun_tap::{Iface, Mode};
use std::sync::Arc;
use std::net::Ipv4Addr;
use packet::ip::v4;
use packet::Builder;
use byteorder::{ByteOrder, BigEndian};

const NAT_PREFIX_MASK: u128 = (!0u128) << 32;

pub struct Tun {
    iface: Iface,
    config: Arc<Config>,
}

impl Tun {
    pub fn new_leaking_name(config: Arc<Config>) -> Result<Tun, String> {
        let boxed_iface_name = config.iface_name.clone();
        let iface_name = unsafe {
            std::mem::transmute::<&str, &'static str>(boxed_iface_name.as_str())
        };
        std::mem::forget(boxed_iface_name);

        Ok(Tun {
            iface: Iface::without_packet_info(iface_name, Mode::Tun).map_err(|e| format!("error creating iface: {:?}", e))?,
            config: config,
        })
    }

    pub fn run(&mut self) {
        let mut buf: [u8; 1500] = [0; 1500];
        loop {
            let n = self.iface.recv(&mut buf).unwrap();
            let buf = &buf[..n];
            match v4::Packet::new(buf) {
                Ok(pkt) => self.handle_ipv4(pkt, buf),
                Err(_) => self.handle_ipv6(buf),
            };
        }
    }

    fn handle_ipv4(&mut self, pkt: v4::Packet<&[u8]>, raw: &[u8]) {
        if raw.len() < 20 {
            return;
        }

        let mut out = vec![0; 40 + (raw.len() - 20)];

        out[0] = 0x60; // Protocol version

        BigEndian::write_u16(&mut out[4..6], (raw.len() - 20) as u16); // Payload size

        out[6] = pkt.protocol().into(); // Protocol number
        out[7] = pkt.ttl(); // Hop limit

        // Source address
        BigEndian::write_u128(&mut out[8..24], (u128::from(self.config.left) & NAT_PREFIX_MASK) | u32::from(pkt.source()) as u128);
        // Destination address
        BigEndian::write_u128(&mut out[24..40], (u128::from(self.config.right) & NAT_PREFIX_MASK) | u32::from(pkt.destination()) as u128);

        // Payload
        out[40..].copy_from_slice(&raw[20..]);

        match self.iface.send(&out) {
            _ => {}
        }
    }

    fn handle_ipv6(&mut self, pkt: &[u8]) {
        if pkt.len() < 40 {
            return;
        }

        if (pkt[0] >> 4) & 0xf != 6 {
            return;
        }

        let payload_length = BigEndian::read_u16(&pkt[4..6]) as usize;
        if payload_length != pkt[40..].len() {
            return;
        }
        let protocol = pkt[6];
        let hop_limit = pkt[7];
        let src_addr = BigEndian::read_u128(&pkt[8..24]);
        let dst_addr = BigEndian::read_u128(&pkt[24..40]);

        let left = u128::from(self.config.left);
        let right = u128::from(self.config.right);

        if src_addr & NAT_PREFIX_MASK == right & NAT_PREFIX_MASK && dst_addr & NAT_PREFIX_MASK == left & NAT_PREFIX_MASK {
            let src_addr = Ipv4Addr::from(src_addr as u32);
            let dst_addr = Ipv4Addr::from(dst_addr as u32);
            let out = v4::Builder::default()
                .ttl(hop_limit).unwrap()
                .source(src_addr).unwrap()
                .destination(dst_addr).unwrap()
                .protocol(protocol.into()).unwrap()
                .payload(&pkt[40..]).unwrap()
                .build().unwrap();
            match self.iface.send(&out) {
                _ => {}
            }
        }
    }
}
