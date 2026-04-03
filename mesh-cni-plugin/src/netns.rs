use crate::Result;

pub(crate) struct NetnsRestore(netns_rs::NetNs);

impl NetnsRestore {
    pub(crate) fn current_thread() -> Result<Self> {
        Ok(Self(netns_rs::get_from_current_thread()?))
    }
}

impl Drop for NetnsRestore {
    fn drop(&mut self) {
        let _ = self.0.enter();
    }
}
