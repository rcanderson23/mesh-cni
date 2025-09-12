pub mod ip;
pub mod loader;
pub mod service;

use std::borrow::BorrowMut;
use std::hash::Hash;

use aya::Pod;
use aya::maps::{HashMap, MapData};

use crate::Result;

pub trait BpfMap<K, V> {
    fn update(&mut self, key: K, value: V) -> Result<()>;
    fn delete(&mut self, key: &K) -> Result<()>;
    fn get(&self, key: &K) -> Result<V>;
    fn get_state(&self) -> Result<ahash::HashMap<K, V>>;
}
pub trait TestBpfMap {
    type Key;
    type Value;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()>;
    fn delete(&mut self, key: &Self::Key) -> Result<()>;
    fn get(&self, key: &Self::Key) -> Result<Self::Value>;
    fn get_state(&self) -> Result<ahash::HashMap<Self::Key, Self::Value>>;
}

impl<T: BorrowMut<MapData>, K: Pod + Eq + Hash, V: Pod> BpfMap<K, V> for HashMap<T, K, V> {
    fn update(&mut self, key: K, value: V) -> Result<()> {
        Ok(self.insert(key, value, 0)?)
    }
    fn delete(&mut self, key: &K) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &K) -> Result<V> {
        Ok(<HashMap<T, K, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<K, V>> {
        let mut map = ahash::HashMap::default();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}
impl<K: Pod + Eq + Hash, V: Pod> BpfMap<K, V> for ahash::HashMap<K, V> {
    fn update(&mut self, key: K, value: V) -> Result<()> {
        self.insert(key, value);
        Ok(())
    }
    fn delete(&mut self, key: &K) -> Result<()> {
        self.remove(key);
        Ok(())
    }
    fn get(&self, key: &K) -> Result<V> {
        match <ahash::HashMap<K, V>>::get(self, key) {
            Some(i) => Ok(*i),
            None => Err(crate::Error::Other("not found".into())),
        }
    }
    fn get_state(&self) -> Result<ahash::HashMap<K, V>> {
        Ok(self.clone())
    }
}

pub struct BpfState<M, K, V>
where
    M: BpfMap<K, V>,
    K: std::hash::Hash + std::cmp::Eq + Clone,
    V: Clone + std::cmp::PartialEq,
{
    cache: ahash::HashMap<K, V>,
    bpf_map: M,
}

impl<M, K, V> BpfState<M, K, V>
where
    M: BpfMap<K, V>,
    K: std::hash::Hash + std::cmp::Eq + Clone,
    V: Clone + std::cmp::PartialEq,
{
    pub fn new(bpf_map: M) -> Self {
        let cache = ahash::HashMap::default();
        Self { cache, bpf_map }
    }

    pub fn update(&mut self, key: K, value: V) -> Result<()> {
        if let Some(current) = self.cache.get(&key)
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key.clone(), value.clone()) {
            Ok(_) => {
                self.cache.insert(key, value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &K) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_from_cache(&self, key: &K) -> Option<&V> {
        if let Some(val) = self.cache.get(key) {
            Some(val)
        } else {
            None
        }
    }
    pub fn get_from_map(&self, key: &K) -> Result<V> {
        self.bpf_map.get(key)
    }
}
