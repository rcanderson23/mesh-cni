use std::path::PathBuf;

pub const BPF_MESH_FS_DIR: &str = "/sys/fs/bpf/mesh";
pub const BPF_MESH_MAPS_DIR: &str = "/sys/fs/bpf/mesh/maps";
pub const BPF_MESH_PROG_DIR: &str = "/sys/fs/bpf/mesh/programs";
pub const BPF_MESH_LINKS_DIR: &str = "/sys/fs/bpf/mesh/links";

pub const BPF_LINK_CGROUP_CONNECT_V4_PATH: &str = "/sys/fs/bpf/mesh/links/mesh_cni_cgroup_connect4";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfNamePath {
    Map(&'static str),
    Program(&'static str),
}

impl BpfNamePath {
    pub const fn name(&self) -> &'static str {
        match self {
            BpfNamePath::Map(name) | BpfNamePath::Program(name) => name,
        }
    }

    pub fn path(&self) -> PathBuf {
        match self {
            BpfNamePath::Map(name) => PathBuf::from(BPF_MESH_MAPS_DIR).join(name),
            BpfNamePath::Program(name) => PathBuf::from(BPF_MESH_PROG_DIR).join(name),
        }
    }
}

pub const BPF_PROGRAM_INGRESS_TC: BpfNamePath = BpfNamePath::Program("mesh_cni_ingress");
pub const BPF_PROGRAM_EGRESS_TC: BpfNamePath = BpfNamePath::Program("mesh_cni_egress");
pub const BPF_PROGRAM_NODEPORT_INGRESS_TC: BpfNamePath =
    BpfNamePath::Program("mesh_cni_nodeport_ingress");
pub const BPF_PROGRAM_NODEPORT_EGRESS_TC: BpfNamePath =
    BpfNamePath::Program("mesh_cni_nodeport_egress");
pub const BPF_PROGRAM_CGROUP_CONNECT_V4: BpfNamePath =
    BpfNamePath::Program("mesh_cni_cgroup_connect4");
pub const BPF_PROGRAM_VXLAN_VETH_EGRESS_TC: BpfNamePath =
    BpfNamePath::Program("mesh_cni_vxlan_veth_egress");
pub const BPF_PROGRAM_VXLAN_NODE_INGRESS_TC: BpfNamePath =
    BpfNamePath::Program("mesh_cni_vxlan_node_ingress");

pub const BPF_MAP_IDENTITY_V4: BpfNamePath = BpfNamePath::Map("identity_v4");
pub const BPF_MAP_IDENTITY_V6: BpfNamePath = BpfNamePath::Map("identity_v6");
pub const BPF_MAP_CONNTRACK_V4: BpfNamePath = BpfNamePath::Map("conntrack_v4");
pub const BPF_MAP_SERVICES_V4: BpfNamePath = BpfNamePath::Map("services_v4");
pub const BPF_MAP_SERVICES_V6: BpfNamePath = BpfNamePath::Map("services_v6");
pub const BPF_MAP_ENDPOINTS_V4: BpfNamePath = BpfNamePath::Map("endpoints_v4");
pub const BPF_MAP_ENDPOINTS_V6: BpfNamePath = BpfNamePath::Map("endpoints_v6");
pub const BPF_MAP_NODEPORT_LOCAL_ADDRS_V4: BpfNamePath =
    BpfNamePath::Map("nodeport_local_addrs_v4");
pub const BPF_MAP_NODEPORT_SERVICES_V4: BpfNamePath = BpfNamePath::Map("nodeport_services_v4");
pub const BPF_MAP_NODEPORT_REV_NAT_V4: BpfNamePath = BpfNamePath::Map("nodeport_rev_nat_v4");
pub const BPF_MAP_NODEPORT_CONNTRACK_V4: BpfNamePath = BpfNamePath::Map("nodeport_conntrack_v4");
pub const BPF_MAP_FRAGMENT_V4: BpfNamePath = BpfNamePath::Map("fragment_v4");
pub const BPF_MAP_POLICY_INDEX: BpfNamePath = BpfNamePath::Map("policy_index");
pub const BPF_MAP_POLICY_RULESET: BpfNamePath = BpfNamePath::Map("policy_ruleset");
pub const BPF_MAP_POLICY_CIDR_V4: BpfNamePath = BpfNamePath::Map("policy_cidr_v4");
pub const BPF_MAP_POLICY_CIDR_V6: BpfNamePath = BpfNamePath::Map("policy_cidr_v6");
pub const BPF_MAP_ROUTER_V4: BpfNamePath = BpfNamePath::Map("router_v4");
