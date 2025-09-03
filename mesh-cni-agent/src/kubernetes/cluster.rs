use std::path::Path;

use kube::config::KubeConfigOptions;
use serde::Deserialize;

use crate::kubernetes::ClusterId;

use crate::Result;

pub struct Cluster {
    pub id: ClusterId,
    pub name: String,
    client: Option<kube::Client>,
}

impl Cluster {
    pub async fn try_new(config: Config) -> Result<Self> {
        let client = if config.context.is_some() {
            let config = kube::Config::from_kubeconfig(&KubeConfigOptions {
                context: config.context,
                ..Default::default()
            })
            .await?;
            kube::Client::try_from(config)?
        } else {
            kube::Client::try_default().await?
        };

        Ok(Self {
            id: config.id,
            name: config.name,
            client: Some(client),
        })
    }

    pub fn take_client(&mut self) -> Option<kube::Client> {
        self.client.take()
    }
}

#[derive(Clone, Deserialize)]
pub struct ClusterConfigs {
    pub local: Config,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote: Vec<Config>,
}

impl ClusterConfigs {
    pub async fn try_new_configs(path: impl AsRef<Path>) -> Result<Self> {
        let config = tokio::fs::read_to_string(path).await?;
        let config = serde_yaml::from_str(&config)?;

        Ok(config)
    }
}

#[derive(Clone, Deserialize)]
pub struct Config {
    pub id: ClusterId,

    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}
