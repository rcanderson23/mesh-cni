use network_types::ip::Ipv4Hdr;

/// Fragement timeout set to 30s matching linux kernel default
// https://docs.kernel.org/5.10/networking/ip-sysctl.html
pub const FRAG_TIMEOUT: u64 = 30 * 1_000_000_000;

#[inline]
pub fn is_first_frag_v4(hdr: &Ipv4Hdr) -> bool {
    more_frags_v4(hdr) && hdr.frag_offset() == 0
}

#[inline]
pub fn is_middle_frag_v4(hdr: &Ipv4Hdr) -> bool {
    more_frags_v4(hdr) && hdr.frag_offset() > 0
}

#[inline]
pub fn is_last_frag_v4(hdr: &Ipv4Hdr) -> bool {
    !(more_frags_v4(hdr)) && hdr.frag_offset() > 0
}

#[inline]
fn more_frags_v4(hdr: &Ipv4Hdr) -> bool {
    (hdr.frag_flags() & 1) != 0
}
