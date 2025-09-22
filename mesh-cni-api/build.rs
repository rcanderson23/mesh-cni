use std::path::{Path, PathBuf};

fn main() -> anyhow::Result<()> {
    let proto_dir = PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "proto"]);
    let protos = get_proto_files(proto_dir.as_path())?;

    tonic_prost_build::configure()
        .type_attribute(
            "cni.v1.IP",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .message_attribute("cni.v1.IP", "#[serde(rename_all = \"camelCase\" )]")
        .type_attribute(
            "cni.v1.DNS",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .message_attribute("cni.v1.DNS", "#[serde(rename_all = \"camelCase\" )]")
        .field_attribute(
            "cni.v1.DNS.nameservers",
            "#[serde(default, skip_serializing_if = \"Vec::is_empty\" )]",
        )
        .field_attribute(
            "cni.v1.DNS.domain",
            "#[serde(default, skip_serializing_if = \"Option::is_none\" )]",
        )
        .field_attribute(
            "cni.v1.DNS.search",
            "#[serde(default, skip_serializing_if = \"Vec::is_empty\" )]",
        )
        .field_attribute(
            "cni.v1.DNS.options",
            "#[serde(default, skip_serializing_if = \"Vec::is_empty\" )]",
        )
        .type_attribute(
            "cni.v1.Interface",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "cni.v1.Route",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .message_attribute("cni.v1.Route", "#[serde(rename_all = \"camelCase\" )]")
        .field_attribute(
            "cni.v1.Route.gw",
            "#[serde(default, skip_serializing_if = \"Option::is_none\" )]",
        )
        .field_attribute(
            "cni.v1.Route.mtu",
            "#[serde(default, skip_serializing_if = \"Option::is_none\" )]",
        )
        .field_attribute(
            "cni.v1.Route.advmss",
            "#[serde(default, skip_serializing_if = \"Option::is_none\" )]",
        )
        .field_attribute(
            "cni.v1.Route.table",
            "#[serde(default, skip_serializing_if = \"Option::is_none\" )]",
        )
        .field_attribute(
            "cni.v1.Route.scope",
            "#[serde(default, skip_serializing_if = \"Option::is_none\" )]",
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
