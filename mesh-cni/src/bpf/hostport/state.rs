use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use mesh_cni_ebpf_common::hostport::{HostPortKey, HostPortKeyV4, HostPortValue, HostPortValueV4};
use mesh_cni_hostport_bpf_controller::{Error as ControllerError, HostPortReader, HostPortWriter};

use crate::{
    Result,
    bpf::{BpfMap, is_map_not_found_error},
};

struct Shared<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    state: Mutex<State<M>>,
}

struct State<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    hostport_cache: ahash::HashMap<HostPortKeyV4, HostPortValueV4>,
    hostport_map: M,
}

pub struct HostPortState<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    shared: Arc<Shared<M>>,
}

impl<M> Clone for HostPortState<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<M> HostPortState<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    pub fn try_new(hostport_map: M) -> Result<Self> {
        let hostport_cache = hostport_map.get_state()?;
        let state = State {
            hostport_cache,
            hostport_map,
        };
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(state),
            }),
        })
    }

    pub fn update(&self, key: HostPortKey, value: HostPortValue) -> Result<()> {
        let (key, value) = match (key, value) {
            (HostPortKey::V4(key), HostPortValue::V4(value)) => (key, value),
            (HostPortKey::V6(_), HostPortValue::V6(_)) => return Ok(()),
            _ => return Err(anyhow!("hostport key/value IP families do not match")),
        };

        let mut state = self.shared.state.lock().unwrap();
        if state.hostport_cache.get(&key) == Some(&value) {
            return Ok(());
        }
        state.hostport_map.update(key, value)?;
        state.hostport_cache.insert(key, value);
        Ok(())
    }

    pub fn remove(&self, key: &HostPortKey) -> Result<()> {
        let key = match key {
            HostPortKey::V4(key) => key,
            HostPortKey::V6(_) => return Ok(()),
        };

        let mut state = self.shared.state.lock().unwrap();
        match state.hostport_map.delete(key) {
            Ok(()) => {
                state.hostport_cache.remove(key);
                Ok(())
            }
            Err(err) if is_map_not_found_error(&err) => {
                state.hostport_cache.remove(key);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn state_from_cache(&self) -> ahash::HashMap<HostPortKey, HostPortValue> {
        let state = self.shared.state.lock().unwrap();
        state
            .hostport_cache
            .iter()
            .map(|(key, value)| (HostPortKey::V4(*key), HostPortValue::V4(*value)))
            .collect()
    }
}

impl<M> HostPortWriter for HostPortState<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    fn upsert_hostport(
        &self,
        key: HostPortKey,
        value: HostPortValue,
    ) -> mesh_cni_hostport_bpf_controller::Result<()> {
        HostPortState::update(self, key, value)
            .map_err(|err| ControllerError::BpfState(err.to_string()))
    }

    fn remove_hostport(&self, key: &HostPortKey) -> mesh_cni_hostport_bpf_controller::Result<()> {
        HostPortState::remove(self, key).map_err(|err| ControllerError::BpfState(err.to_string()))
    }
}

impl<M> HostPortReader for HostPortState<M>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>,
{
    fn hostport_state(
        &self,
    ) -> mesh_cni_hostport_bpf_controller::Result<ahash::HashMap<HostPortKey, HostPortValue>> {
        Ok(HostPortState::state_from_cache(self))
    }
}
