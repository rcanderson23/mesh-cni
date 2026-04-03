use std::path::{Path, PathBuf};

fn main() -> anyhow::Result<()> {
    let proto_dir = PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "proto"]);
    let protos = get_proto_files(proto_dir.as_path())?;

    tonic_prost_build::configure()
        .type_attribute(
            "ip.v1.IpId",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "service.v1.ServiceWithEndpoints",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "service.v1.NodePortService",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "conntrack.v1.Connection",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "policy.v1.PolicySet",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .build_client(true)
        .build_server(true)
        .compile_protos(protos.as_slice(), &[proto_dir])?;
    Ok(())
}

fn get_proto_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let paths: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|f| f.file_name().to_string_lossy().ends_with(".proto"))
        .map(|e| e.path().to_owned())
        .collect();

    Ok(paths)
}
