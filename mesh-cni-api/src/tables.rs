use std::borrow::Cow;

use tabled::Tabled;

impl Tabled for crate::ip::v1::IpId {
    const LENGTH: usize = 3;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        let mut labels = String::new();
        for (k, v) in self.labels.iter() {
            labels.push_str(&format!("{}={}\n", k, v));
        }
        vec![
            Cow::Borrowed(&self.ip),
            Cow::Owned(self.id.to_string()),
            Cow::Owned(labels),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            Cow::Borrowed("IP"),
            Cow::Borrowed("ID"),
            Cow::Borrowed("LABELS"),
        ]
    }
}

impl Tabled for crate::service::v1::ServiceWithEndpoints {
    const LENGTH: usize = 3;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        let mut endpoints = String::new();
        for ep in &self.endpoints {
            endpoints.push_str(&format!("{}\n", ep));
        }
        vec![
            Cow::Borrowed(&self.service_endpoint),
            Cow::Borrowed(&self.protocol),
            Cow::Owned(endpoints),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            Cow::Borrowed("SERVICE_ENDPOINT"),
            Cow::Borrowed("PROTOCOL"),
            Cow::Borrowed("BACKEND_ENDPOINTS"),
        ]
    }
}
