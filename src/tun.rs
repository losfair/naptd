use crate::config::*;
use crate::checksum;
use tun_tap::{Iface, Mode};
use std::sync::Arc;
use std::net::{Ipv4Addr, Ipv6Addr};
use packet::ip::{v4, Protocol};
use packet::Builder;
use packet::PacketMut;
use byteorder::{ByteOrder, BigEndian, LittleEndian};

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
            let buf = &mut buf[..n];
            match v4::Packet::new(buf as &[u8]) {
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

        let src_addr = (u128::from(self.config.left) & NAT_PREFIX_MASK) | u32::from(pkt.source()) as u128;
        let dst_addr = (u128::from(self.config.right) & NAT_PREFIX_MASK) | u32::from(pkt.destination()) as u128;

        // Source address
        BigEndian::write_u128(&mut out[8..24], src_addr);
        // Destination address
        BigEndian::write_u128(&mut out[24..40], dst_addr);

        let src_addr = Ipv6Addr::from(src_addr);
        let dst_addr = Ipv6Addr::from(dst_addr);

        // Payload
        out[40..].copy_from_slice(&raw[20..]);

        match pkt.protocol() {
            Protocol::Tcp => {
                let payload = &mut out[40..];
                if payload.len() < 20 {
                    return;
                }
                regenerate_protocol_checksum_4to6(payload, 16, pkt.source(), pkt.destination(), src_addr, dst_addr, Protocol::Tcp);
            }
            Protocol::Udp => {
                let payload = &mut out[40..];
                if payload.len() < 8 {
                    return;
                }
                regenerate_protocol_checksum_4to6(payload, 6, pkt.source(), pkt.destination(), src_addr, dst_addr, Protocol::Udp);
            }
            _ => {}
        }

        match self.iface.send(&out) {
            _ => {}
        }
    }

    fn handle_ipv6(&mut self, pkt: &mut [u8]) {
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
            let src_v6 = Ipv6Addr::from(src_addr);
            let dst_v6 = Ipv6Addr::from(dst_addr);
            let src_addr = Ipv4Addr::from(src_addr as u32);
            let dst_addr = Ipv4Addr::from(dst_addr as u32);

            match Protocol::from(protocol) {
                Protocol::Tcp => {
                    let payload = &mut pkt[40..];
                    if payload.len() < 20 {
                        return;
                    }
                    regenerate_protocol_checksum_6to4(payload, 16, src_v6, dst_v6, src_addr, dst_addr, Protocol::Tcp);
                }
                Protocol::Udp => {
                    let payload = &mut pkt[40..];
                    if payload.len() < 8 {
                        return;
                    }
                    regenerate_protocol_checksum_6to4(payload, 6, src_v6, dst_v6, src_addr, dst_addr, Protocol::Udp);
                }
                _ => {}
            }

            let mut out = v4::Builder::default()
                .ttl(hop_limit).unwrap()
                .source(src_addr).unwrap()
                .destination(dst_addr).unwrap()
                .protocol(protocol.into()).unwrap()
                .payload(&pkt[40..]).unwrap()
                .build().unwrap();

            // FIXME: Currently the `packet` crate incorrectly uses the size of the whole packet in the IHL field.
            // This is a workaround.
            {
                let mut out = v4::Packet::unchecked(&mut out);
                out.as_mut()[0] = 0x45;
                out.update_checksum().unwrap();
            }

            match self.iface.send(&out) {
                _ => {}
            }
        }
    }
}

fn regenerate_protocol_checksum_6to4(payload: &mut [u8], begin: usize, src_v6: Ipv6Addr, dst_v6: Ipv6Addr, src_v4: Ipv4Addr, dst_v4: Ipv4Addr, protocol: Protocol) {
    // Checksum inputs/outputs should all be in the "original" network byte order so using LittleEndian here.
    let old_checksum = LittleEndian::read_u16(&payload[begin..]);
    let old_hdr_cs = checksum::ipv6_pseudo_header_checksum(src_v6, dst_v6, payload.len() as u32, protocol.into());
    let new_hdr_cs = checksum::ipv4_pseudo_header_checksum(src_v4, dst_v4, payload.len() as u16, protocol.into());
    LittleEndian::write_u16(&mut payload[begin..], checksum::ip_checksum_adjust(old_checksum, old_hdr_cs, new_hdr_cs));
}

fn regenerate_protocol_checksum_4to6(payload: &mut [u8], begin: usize, src_v4: Ipv4Addr, dst_v4: Ipv4Addr, src_v6: Ipv6Addr, dst_v6: Ipv6Addr, protocol: Protocol) {
    // Checksum inputs/outputs should all be in the "original" network byte order so using LittleEndian here.
    let old_checksum = LittleEndian::read_u16(&payload[begin..]);
    let old_hdr_cs = checksum::ipv4_pseudo_header_checksum(src_v4, dst_v4, payload.len() as u16, protocol.into());
    let new_hdr_cs = checksum::ipv6_pseudo_header_checksum(src_v6, dst_v6, payload.len() as u32, protocol.into());
    LittleEndian::write_u16(&mut payload[begin..], checksum::ip_checksum_adjust(old_checksum, old_hdr_cs, new_hdr_cs));
}