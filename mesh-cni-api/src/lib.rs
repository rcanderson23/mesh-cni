pub mod tables;
pub mod bpf {
    pub mod v1 {
        tonic::include_proto!("grpc.bpf.v1");
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
