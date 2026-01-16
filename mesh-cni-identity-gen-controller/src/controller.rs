use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Duration,
};

use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{
    Api, ResourceExt,
    api::{DeleteParams, Patch, PatchParams},
    runtime::{controller::Action, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::identity::{Identity, IdentitySpec};
use rand::Rng;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::{Error, Result, context::Context};

const MANANGER: &str = "identity-gen-controller";

#[tracing::instrument(skip(ctx, ns))]
pub(crate) async fn reconcile_namespace(ns: Arc<Namespace>, ctx: Arc<Context>) -> Result<Action> {
    let name = ns.name_any();
    tracing::info!("reconcile namespace {}", name);

    let identity_api: Api<Identity> = Api::namespaced(ctx.client.clone(), &name);
    let params = PatchParams::apply(MANANGER).force();
    let mut desired_names = HashSet::new();
    let mut desired_identities = Vec::new();

    for pod in ctx.pods.state() {
        if pod.namespace().as_deref() != Some(&name) {
            continue;
        }
        let identity = get_or_generate_identity(&ctx, &ns, &pod)?;
        if let Some(identity_name) = identity.metadata.name.clone() {
            desired_names.insert(identity_name);
            desired_identities.push(identity);
        }
    }

    for identity in desired_identities {
        let identity_name = identity
            .metadata
            .name
            .clone()
            .ok_or_else(|| Error::InvalidResource)?;
        identity_api
            .patch(&identity_name, &params, &Patch::Apply(&identity))
            .await?;
    }

    for identity in ctx.identities.state() {
        if identity.namespace().as_deref() != Some(&name) {
            continue;
        }
        let Some(identity_name) = identity.metadata.name.clone() else {
            continue;
        };
        if desired_names.contains(&identity_name) {
            continue;
        }
        identity_api
            .delete(&identity_name, &DeleteParams::default())
            .await?;
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

// TODO: revisit error handling and backoff strategy once controller logic is defined.
pub(crate) fn error_policy<K>(k: Arc<K>, error: &Error, _ctx: Arc<Context>) -> Action
where
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
{
    let name = k.name_any();
    let ns = k.namespace().unwrap_or_default();
    tracing::error!(?error, "reconcile error for {}/{}", ns, name);
    Action::requeue(Duration::from_secs(1))
}

fn get_or_generate_identity(ctx: &Context, ns: &Namespace, pod: &Pod) -> Result<Identity> {
    let mut pod_labels = pod.labels().to_owned();
    sanitize_pod_labels(&mut pod_labels);

    let mut spec = IdentitySpec {
        namespace_labels: ns.labels().to_owned(),
        pod_labels,
        id: 0,
    };

    let spec_bytes = serde_json::to_vec(&spec).map_err(|_| Error::HashConversionFailure)?;
    let mut hasher = Sha256::new();
    hasher.update(&spec_bytes);
    let name = format!("{:x}", hasher.finalize());

    if let Some(ident) = ctx
        .identities
        .get(&ObjectRef::new(&name).within(&ns.name_any()))
    {
        let mut ident = (*ident).clone();

        // SSA requires managedFields to be omitted from the payload.
        ident.metadata.managed_fields = None;
        return Ok(ident);
    }

    let mut used_ids = HashSet::new();
    for identity in ctx.identities.state() {
        used_ids.insert(identity.spec.id);
    }
    let mut rng = rand::rng();
    spec.id = loop {
        let candidate = rng.random();
        if !used_ids.contains(&candidate) {
            break candidate;
        }
    };

    Ok(Identity::new(&name, spec))
}

fn sanitize_pod_labels(labels: &mut BTreeMap<String, String>) {
    let removal_list = [
        "controller-revision-hash",
        "pod-template-hash",
        "pod-template-generation",
    ];

    removal_list.iter().for_each(|i| {
        labels.remove(*i);
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use http::Uri;
    use k8s_openapi::api::core::v1::{Namespace, Pod};
    use kube::{
        Client,
        api::ObjectMeta,
        config::Config,
        runtime::{reflector::store, watcher},
    };

    use super::*;

    fn test_client() -> Client {
        let config = Config::new(Uri::from_static("http://localhost"));
        Client::try_from(config).expect("test client")
    }

    fn make_context(pods: Vec<Pod>, identities: Vec<Identity>) -> Context {
        let (pod_store, mut pod_writer) = store();
        for pod in pods {
            pod_writer.apply_watcher_event(&watcher::Event::Apply(pod));
        }

        let (identity_store, mut identity_writer) = store();
        for identity in identities {
            identity_writer.apply_watcher_event(&watcher::Event::Apply(identity));
        }

        let client = test_client();

        Context {
            client,
            pods: pod_store,
            identities: identity_store,
        }
    }

    fn make_namespace(name: &str) -> Namespace {
        let mut labels = BTreeMap::new();
        labels.insert("env".into(), "test".into());
        Namespace {
            metadata: ObjectMeta {
                name: Some(name.into()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_pod(name: &str, namespace: &str) -> Pod {
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "demo".into());
        labels.insert("controller-revision-hash".into(), "remove".into());
        Pod {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn hash_identity_spec(spec: &IdentitySpec) -> String {
        let spec_bytes = serde_json::to_vec(spec).expect("spec to vec");
        let mut hasher = Sha256::new();
        hasher.update(&spec_bytes);
        format!("{:x}", hasher.finalize())
    }

    #[tokio::test]
    async fn test_generate_identity_new() {
        let ns = make_namespace("ns-a");
        let pod = make_pod("pod-a", "ns-a");
        let existing = Identity {
            metadata: ObjectMeta {
                name: Some("other".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: IdentitySpec {
                namespace_labels: BTreeMap::new(),
                pod_labels: BTreeMap::new(),
                id: 123,
            },
        };
        let ctx = make_context(vec![pod.clone()], vec![existing]);

        let identity = get_or_generate_identity(&ctx, &ns, &pod).expect("identity");
        assert_ne!(identity.spec.id, 123);

        let mut expected_pod_labels = pod.labels().to_owned();
        sanitize_pod_labels(&mut expected_pod_labels);
        let expected_spec = IdentitySpec {
            namespace_labels: ns.labels().to_owned(),
            pod_labels: expected_pod_labels,
            id: 0,
        };
        let expected_name = hash_identity_spec(&expected_spec);
        assert_eq!(
            identity.metadata.name.as_deref(),
            Some(expected_name.as_str())
        );
    }

    #[tokio::test]
    async fn test_generate_identity_existing() {
        let ns = make_namespace("ns-a");
        let pod = make_pod("pod-a", "ns-a");
        let mut pod_labels = pod.labels().to_owned();
        sanitize_pod_labels(&mut pod_labels);
        let spec = IdentitySpec {
            namespace_labels: ns.labels().to_owned(),
            pod_labels,
            id: 0,
        };
        let name = hash_identity_spec(&spec);
        let existing = Identity {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: spec.clone(),
        };
        let ctx = make_context(vec![pod.clone()], vec![existing.clone()]);

        let identity = get_or_generate_identity(&ctx, &ns, &pod).expect("identity");
        assert_eq!(identity.metadata.name.as_deref(), Some(name.as_str()));
        assert_eq!(identity.spec, existing.spec);
    }
}
