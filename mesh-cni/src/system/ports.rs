use std::{fs, io::ErrorKind};

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::{Result, config::NodePortSettings};

const LOCAL_RESERVED_PORT_IPV4: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";
const LOCAL_RESERVED_PORT_IPV6: &str = "/proc/sys/net/ipv6/ip_local_reserved_ports";

pub(crate) fn ensure_node_ports_settings(settings: &NodePortSettings) -> Result<()> {
    if settings.node_port_start > settings.node_port_end {
        bail!(
            "node_port_end ({}) must be greater than or equal to node_port_start ({})",
            settings.node_port_end,
            settings.node_port_start
        );
    }

    let range = format!("{}-{}", settings.node_port_start, settings.node_port_end);
    info!(range = %range, "ensuring node port range is reserved");

    ensure_reserved_ports_file(
        LOCAL_RESERVED_PORT_IPV4,
        settings.node_port_start,
        settings.node_port_end,
        true,
    )?;
    ensure_reserved_ports_file(
        LOCAL_RESERVED_PORT_IPV6,
        settings.node_port_start,
        settings.node_port_end,
        false,
    )?;

    Ok(())
}

fn ensure_reserved_ports_file(
    path: &str,
    node_port_start: u16,
    node_port_end: u16,
    required: bool,
) -> Result<()> {
    let current = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(err) if !required && err.kind() == ErrorKind::NotFound => {
            info!(
                path,
                "skipping optional reserved ports path that does not exist"
            );
            return Ok(());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("read {path}"));
        }
    };

    let current_ranges = parse_reserved_ports(current.trim())?;
    let merged_ranges = merge_range(current_ranges, (node_port_start, node_port_end));
    let desired = format_ranges(&merged_ranges);

    if desired == current.trim() {
        info!(path, value = %desired, "reserved ports already up to date");
        return Ok(());
    }

    match fs::write(path, &desired) {
        Ok(()) => {
            info!(path, value = %desired, "updated reserved ports");
            Ok(())
        }
        Err(err) if !required && err.kind() == ErrorKind::NotFound => {
            warn!(path, %err, "optional reserved ports path disappeared during update");
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("write {path}")),
    }
}

fn parse_reserved_ports(value: &str) -> Result<Vec<(u16, u16)>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut ranges = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let (start, end) = match token.split_once('-') {
            Some((start, end)) => (
                parse_port(start).with_context(|| format!("parse start port in '{token}'"))?,
                parse_port(end).with_context(|| format!("parse end port in '{token}'"))?,
            ),
            None => {
                let port = parse_port(token).with_context(|| format!("parse port in '{token}'"))?;
                (port, port)
            }
        };

        if start > end {
            bail!("reserved port range start {start} must be <= end {end}");
        }
        ranges.push((start, end));
    }

    Ok(normalize_ranges(ranges))
}

fn parse_port(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("invalid port '{value}'"))
}

fn merge_range(mut ranges: Vec<(u16, u16)>, new_range: (u16, u16)) -> Vec<(u16, u16)> {
    ranges.push(new_range);
    normalize_ranges(ranges)
}

fn normalize_ranges(mut ranges: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    if ranges.is_empty() {
        return ranges;
    }

    ranges.sort_unstable_by_key(|(start, _)| *start);

    let mut normalized = Vec::with_capacity(ranges.len());
    let mut current = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        let contiguous_or_overlap = start <= current.1.saturating_add(1);
        if contiguous_or_overlap {
            current.1 = current.1.max(end);
        } else {
            normalized.push(current);
            current = (start, end);
        }
    }
    normalized.push(current);
    normalized
}

fn format_ranges(ranges: &[(u16, u16)]) -> String {
    ranges
        .iter()
        .map(|(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::{format_ranges, merge_range, parse_reserved_ports};

    #[test]
    fn parse_reserved_ports_handles_single_and_range_values() {
        let ranges = parse_reserved_ports("22,80,30000-32767").expect("parse should work");
        assert_eq!(ranges, vec![(22, 22), (80, 80), (30000, 32767)]);
    }

    #[test]
    fn merge_range_preserves_existing_and_adds_node_port_range() {
        let existing = parse_reserved_ports("22,2379-2380").expect("parse should work");
        let merged = merge_range(existing, (30000, 32767));
        assert_eq!(format_ranges(&merged), "22,2379-2380,30000-32767");
    }

    #[test]
    fn merge_range_coalesces_overlapping_and_adjacent_ranges() {
        let existing = parse_reserved_ports("29000-30012,32500-40000").expect("parse should work");
        let merged = merge_range(existing, (23900, 32767));
        assert_eq!(format_ranges(&merged), "23900-40000");
    }
}
