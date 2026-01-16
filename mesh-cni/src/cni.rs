use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mesh_cni_plugin::{
    CNI_VERSION,
    config::{Config, PluginConfig},
};
use serde_json::Value;
use tracing::{info, warn};

use crate::{Result, config::AgentArgs};

const CONFLIST_NAME: &str = "05-mesh.conflist";

pub async fn ensure_cni_preconditions(args: &AgentArgs) -> Result<()> {
    ensure_cni_log_dir(&args.cni_plugin_log_dir)?;
    ensure_cni_bin(&args.cni_bin_dir, &args.cni_plugin_bin)?;
    let conf = if args.chained {
        // first startup can have issues where the main CNI has not written its
        // conf yet so retry a few times before completely failing
        let mut attempts = 0;
        let max_attempts = 3;
        let existing_conf = loop {
            match get_existing_conflist(&args.cni_conf_dir) {
                Ok(c) => break c,
                Err(e) => {
                    if attempts >= max_attempts {
                        return Err(e);
                    }
                    attempts += 1;
                    warn!(%e, "failed to get existing conflist, retrying");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        };
        update_cni_conf(&existing_conf)?
    } else {
        default_cni_config()?
    };
    ensure_cni_conf(&args.cni_conf_dir, &conf)?;
    Ok(())
}

fn ensure_cni_log_dir(dst: impl AsRef<Path>) -> Result<()> {
    info!("creating cni plugin log directory");
    fs::create_dir_all(dst).map_err(|e| e.into())
}

fn ensure_cni_conf(cni_conf_dir: impl AsRef<Path>, existing_conf: &[u8]) -> Result<()> {
    info!("creating cni configuration");
    let mut path = PathBuf::new();
    path.push(cni_conf_dir);
    path.push(CONFLIST_NAME);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(existing_conf)?;
    Ok(())
}

// Returns the first conflist if found, then checks for conf
fn get_existing_conflist(cni_conf_dir: impl AsRef<Path>) -> Result<Vec<u8>> {
    let mut files: Vec<_> = fs::read_dir(cni_conf_dir)?
        .filter_map(|f| {
            let Ok(f) = f else { return None };
            if f.file_name() != CONFLIST_NAME {
                Some(f)
            } else {
                None
            }
        })
        .collect();

    files.sort_by_key(|d| d.path());

    info!("checking for conflist");
    let conflist = files
        .iter()
        .filter_map(|f| {
            if Path::new(&f.path()).extension() == Some(OsStr::new("conflist")) {
                Some(f.path())
            } else {
                None
            }
        })
        .next();
    if let Some(conflist) = conflist {
        let conflist = fs::read(conflist)?;
        return Ok(conflist);
    }

    info!("checking for conf");
    let conf = files
        .iter()
        .filter(|f| f.path().extension() == Some(OsStr::new("conf")))
        .map(|f| f.path())
        .next();
    if let Some(conf) = conf {
        let conf = fs::read(conf)?;
        return Ok(conf);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "existing conflist/conf file not found".to_string(),
    )
    .into())
}

fn ensure_cni_bin(dst: impl AsRef<Path>, bin_path: impl AsRef<Path>) -> Result<()> {
    info!("copying plugin to cni bin");
    let mut path = PathBuf::new();
    path.push(dst);
    path.push("mesh-cni");
    fs::copy(bin_path, &path)?;
    let permissions = fs::Permissions::from_mode(0o755);
    fs::set_permissions(path, permissions)?;

    Ok(())
}

fn default_cni_config() -> Result<Vec<u8>> {
    let conf = Config {
        cni_version: CNI_VERSION,
        cni_versions: vec![CNI_VERSION],
        name: "mesh-cni".into(),
        disable_check: None,
        disable_gc: None,
        load_only_inlined_plugins: None,
        plugins: Vec::new(),
    };
    serde_json::to_vec_pretty(&conf).map_err(|e| e.into())
}

// updates the existing cni config to include mesh-cni plugin
fn update_cni_conf(conf: &[u8]) -> Result<Vec<u8>> {
    let mut conf: mesh_cni_plugin::config::Config = serde_json::from_slice(conf)?;
    let mut options = HashMap::new();
    options.insert("chained".into(), Value::Bool(true));
    conf.plugins.push(PluginConfig {
        r#type: "mesh-cni".into(),
        options,
    });

    serde_json::to_vec_pretty(&conf).map_err(|e| e.into())
}

// #[cfg(test)]
// mod test {
//
//     use super::*;
//
//     #[test]
//     fn name() {
//         todo!();
//     }
// }
