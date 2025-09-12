use std::net::IpAddr;

use ahash::HashMap;
use mesh_cni_common::Id;

use crate::Result;
use crate::bpf::{BpfMap, BpfState};
use crate::kubernetes::Labels;

pub type Ipv4State<I> = BpfState<I, u32, Id>;
pub type Ipv6State<P> = BpfState<P, u128, Id>;

// replace map with https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LPM_TRIE/
pub struct State<I, P>
where
    I: BpfMap<u32, Id>,
    P: BpfMap<u128, Id>,
{
    pub ip_to_labels_id: HashMap<IpAddr, (Labels, Id)>,
    pub labels_to_id: HashMap<Labels, Id>,
    ipv4_state: Ipv4State<I>,
    ipv6_state: Ipv6State<P>,
    id: Id,
}

impl<I, P> State<I, P>
where
    I: BpfMap<u32, Id>,
    P: BpfMap<u128, Id>,
{
    pub fn new(ipv4_map: I, ipv6_map: P) -> Self {
        let ipv4_state = BpfState::new(ipv4_map);
        let ipv6_state = BpfState::new(ipv6_map);
        Self {
            labels_to_id: HashMap::default(),
            ip_to_labels_id: HashMap::default(),
            // id less than 128 are reserved for cluster specific items
            id: 128,
            ipv4_state,
            ipv6_state,
        }
    }
    // TODO: check if this can error with notifications
    pub async fn insert(&mut self, ip: IpAddr, labels: &Labels) -> Result<()> {
        if let Some((current_labels, _id)) = self.ip_to_labels_id.get(&ip)
            && *current_labels == *labels
        {
            return Ok(());
        }

        match ip {
            IpAddr::V4(ipv4_addr) => self.ipv4_state.update(ipv4_addr.to_bits(), self.id)?,
            IpAddr::V6(ipv6_addr) => self.ipv6_state.update(ipv6_addr.to_bits(), self.id)?,
        };
        let _ = self.labels_to_id.insert(labels.clone(), self.id);
        let _ = self
            .ip_to_labels_id
            .insert(ip, (labels.to_owned(), self.id));

        self.id += 1;

        Ok(())
    }

    pub fn delete(&mut self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4_addr) => self.ipv4_state.delete(&ipv4_addr.to_bits())?,
            IpAddr::V6(ipv6_addr) => self.ipv6_state.delete(&ipv6_addr.to_bits())?,
        }
        let labels_id = self.ip_to_labels_id.remove(&ip);
        if let Some((labels, _id)) = labels_id {
            self.labels_to_id.remove(&labels);
        };
        Ok(())
    }

    pub fn get_id_from_labels(&self, labels: &Labels) -> Option<Id> {
        self.labels_to_id.get(labels).cloned()
    }
}
