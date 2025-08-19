use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mesh_cni::config::PluginConfig;
use tracing::info;

use crate::Result;
use crate::config::ControllerArgs;

const CNI_PATH: &str = "./mesh-cni";
const CONFLIST_NAME: &str = "05-mesh.conflist";

pub fn ensure_cni_preconditions(args: &ControllerArgs) -> Result<()> {
    ensure_cni_log_dir(&args.cni_plugin_log_dir)?;
    ensure_cni_bin(&args.cni_bin_dir)?;
    let existing_conf = get_existing_conflist(&args.cni_conf_dir)?;
    let existing_conf = update_cni_conf(&existing_conf)?;
    ensure_cni_conf(&args.cni_conf_dir, &existing_conf)?;
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
        .filter_map(|f| {
            if Path::new(&f.path()).extension() == Some(OsStr::new("conf")) {
                Some(f.path())
            } else {
                None
            }
        })
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

fn ensure_cni_bin(dst: impl AsRef<Path>) -> Result<()> {
    info!("copying plugin to cni bin");
    let mut path = PathBuf::new();
    path.push(dst);
    path.push("mesh-cni");
    fs::copy(CNI_PATH, &path)?;
    let permissions = fs::Permissions::from_mode(0o755);
    fs::set_permissions(path, permissions)?;

    Ok(())
}

// updates the existing cni config to include mesh-cni plugin
fn update_cni_conf(conf: &[u8]) -> Result<Vec<u8>> {
    let mut conf: mesh_cni::config::Config = serde_json::from_slice(conf)?;
    conf.plugins.push(PluginConfig {
        r#type: "mesh-cni".into(),
        options: Default::default(),
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
