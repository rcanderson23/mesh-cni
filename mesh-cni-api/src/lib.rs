pub mod tables;

pub mod cni {
    pub mod v1 {
        tonic::include_proto!("grpc.cni.v1");
    }
}

pub mod ip {
    pub mod v1 {
        tonic::include_proto!("grpc.ip.v1");
    }
}

pub mod service {
    pub mod v1 {
        tonic::include_proto!("grpc.service.v1");
    }
}

pub mod conntrack {
    pub mod v1 {
        tonic::include_proto!("grpc.conntrack.v1");
    }
}

pub mod policy {
    pub mod v1 {
        tonic::include_proto!("grpc.policy.v1");
    }
}
