pub mod ip;
pub mod loader;
pub mod service;

use std::borrow::BorrowMut;
use std::hash::Hash;

use aya::Pod;
use aya::maps::lpm_trie::Key as LpmKey;
use aya::maps::{HashMap, LpmTrie, MapData};

use crate::Result;
use crate::bpf::ip::IpNetwork;

pub trait BpfMap {
    type Key;
    type Value;
    type KeyOutput;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()>;
    fn delete(&mut self, key: &Self::Key) -> Result<()>;
    fn get(&self, key: &Self::Key) -> Result<Self::Value>;
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>>;
}

impl<T, K, V> BpfMap for HashMap<T, K, V>
where
    T: BorrowMut<MapData>,
    K: Pod + Eq + Hash,
    V: Pod,
{
    type Key = K;
    type Value = V;
    type KeyOutput = K;
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

impl<K, V> BpfMap for ahash::HashMap<K, V>
where
    K: Pod + Eq + Hash,
    V: Pod,
{
    type Key = K;
    type Value = V;
    type KeyOutput = K;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()> {
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

impl<T, V> BpfMap for LpmTrie<T, u32, V>
where
    T: BorrowMut<MapData>,
    // K: Pod + Eq + Hash + From<LpmKey<>>,
    V: Pod,
{
    type Key = LpmKey<u32>;
    type Value = V;
    type KeyOutput = IpNetwork;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()> {
        Ok(self.insert(&key, value, 0)?)
    }
    fn delete(&mut self, key: &Self::Key) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &Self::Key) -> Result<Self::Value> {
        Ok(<LpmTrie<T, u32, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>> {
        let mut map = ahash::HashMap::default();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    let k = IpNetwork::from(k);
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}
impl<T, V> BpfMap for LpmTrie<T, u128, V>
where
    T: BorrowMut<MapData>,
    // K: Pod + Eq + Hash + From<LpmKey<>>,
    V: Pod,
{
    type Key = LpmKey<u128>;
    type Value = V;
    type KeyOutput = IpNetwork;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()> {
        Ok(self.insert(&key, value, 0)?)
    }
    fn delete(&mut self, key: &Self::Key) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &Self::Key) -> Result<Self::Value> {
        Ok(<LpmTrie<T, u128, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>> {
        let mut map = ahash::HashMap::default();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    let k = IpNetwork::from(k);
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}
