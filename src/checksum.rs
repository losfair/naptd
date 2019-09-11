// Ported from https://android.googlesource.com/platform/system/core/+/master/libnetutils/checksum.c.

use byteorder::{ByteOrder, LittleEndian, BigEndian};
use std::net::{Ipv4Addr, Ipv6Addr};

/* function: ip_checksum_add
 * adds data to a checksum. only known to work on little-endian hosts
 * current - the current checksum (or 0 to start a new checksum)
 *   data        - the data to add to the checksum
 *   len         - length of data
 */
fn ip_checksum_add(current: u32, mut data: &[u8]) -> u32 {
    let mut checksum: u32 = current;
    while data.len() > 1 {
        checksum += LittleEndian::read_u16(data) as u32;
        data = &data[2..];
    }
    if data.len() == 1 {
        checksum += data[0] as u32;
    }
    checksum
}
/* function: ip_checksum_fold
 * folds a 32-bit partial checksum into 16 bits
 *   temp_sum - sum from ip_checksum_add
 *   returns: the folded checksum in network byte order
 */
fn ip_checksum_fold(mut temp_sum: u32) -> u16 {
    while temp_sum > 0xffff {
        temp_sum = (temp_sum >> 16) + (temp_sum & 0xffff);
    }
    temp_sum as u16
}

/* function: ip_checksum_finish
 * folds and closes the checksum
 *   temp_sum - sum from ip_checksum_add
 *   returns: a header checksum value in network byte order
 */
fn ip_checksum_finish(temp_sum: u32) -> u16 {
    !ip_checksum_fold(temp_sum)
}

/* function: ip_checksum
 * combined ip_checksum_add and ip_checksum_finish
 *   data - data to checksum
 *   len  - length of data
 */
fn ip_checksum(data: &[u8]) -> u16 {
    ip_checksum_finish(ip_checksum_add(0, data))
}

/* function: ipv6_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp/icmp headers
 *   ip6      - the ipv6 header
 *   len      - the transport length (transport header + payload)
 *   protocol - the transport layer protocol, can be different from ip6->ip6_nxt for fragments
 */
pub fn ipv6_pseudo_header_checksum(src: Ipv6Addr, dst: Ipv6Addr, len: u32, protocol: u8) -> u32 {
    let mut len_net: [u8; 4] = [0; 4];
    BigEndian::write_u32(&mut len_net, len);

    let protocol_net: [u8; 4] = [0, 0, 0, protocol];
    let mut current: u32 = 0;

    current = ip_checksum_add(current, &src.octets());
    current = ip_checksum_add(current, &dst.octets());
    current = ip_checksum_add(current, &len_net);
    current = ip_checksum_add(current, &protocol_net);
    current
}

/* function: ipv4_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp headers
 *   ip      - the ipv4 header
 *   len     - the transport length (transport header + payload)
 */
pub fn ipv4_pseudo_header_checksum(src: Ipv4Addr, dst: Ipv4Addr, len: u16, protocol: u8) -> u32 {
    let mut len_net: [u8; 2] = [0; 2];
    BigEndian::write_u16(&mut len_net, len);

    let protocol_net: [u8; 2] = [0, protocol];
    let mut current: u32 = 0;

    current = ip_checksum_add(current, &src.octets());
    current = ip_checksum_add(current, &dst.octets());
    current = ip_checksum_add(current, &protocol_net);
    current = ip_checksum_add(current, &len_net);
    current
}

/* function: ip_checksum_adjust
 * calculates a new checksum given a previous checksum and the old and new pseudo-header checksums
 *   checksum    - the header checksum in the original packet in network byte order
 *   old_hdr_sum - the pseudo-header checksum of the original packet
 *   new_hdr_sum - the pseudo-header checksum of the translated packet
 *   returns: the new header checksum in network byte order
 */
pub fn ip_checksum_adjust(checksum: u16, old_hdr_sum: u32, new_hdr_sum: u32) -> u16 {
    let checksum = !checksum;
    let folded_sum: u16 = ip_checksum_fold(checksum as u32 + new_hdr_sum);
    let folded_old: u16 = ip_checksum_fold(old_hdr_sum);
    if folded_sum > folded_old {
        !(folded_sum - folded_old)
    } else {
        !(folded_sum.wrapping_sub(folded_old).wrapping_sub(1)) // end-around borrow
    }
}
