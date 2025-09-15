use std::path::Path;

use http::Uri;
use kube::config::KubeConfigOptions;
use serde::Deserialize;

use crate::kubernetes::ClusterId;

use crate::Result;

#[derive(Clone)]
pub struct Cluster {
    pub id: ClusterId,
    pub name: String,
    client: Option<kube::Client>,
}

impl Cluster {
    pub async fn try_new(config: Config) -> Result<Self> {
        let client_config = if config.context.is_some() {
            kube::Config::from_kubeconfig(&KubeConfigOptions {
                context: config.context,
                ..Default::default()
            })
            .await?
        } else {
            let mut client_config = kube::Config::incluster()?;
            if let Some(endpoint) = config.endpoint {
                client_config.cluster_url = Uri::try_from(endpoint).unwrap();
            }
            client_config
        };

        let client = kube::Client::try_from(client_config)?;
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

    pub context: Option<String>,

    pub endpoint: Option<String>,
}
