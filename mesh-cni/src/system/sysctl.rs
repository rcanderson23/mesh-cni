use std::path::Path;

use crate::Result;

pub(crate) fn disable_rp_filter(name: &str) -> Result<()> {
    std::fs::write(Path::new(&rp_filter_path_v4(name)), b"0\n")?;
    Ok(())
}

fn rp_filter_path_v4(name: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{}/rp_filter", name)
}
