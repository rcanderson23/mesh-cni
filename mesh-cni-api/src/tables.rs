use std::borrow::Cow;

use tabled::Tabled;

impl Tabled for crate::ip::v1::IpId {
    const LENGTH: usize = 2;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        vec![Cow::Borrowed(&self.ip), Cow::Owned(self.id.to_string())]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![Cow::Borrowed("IP"), Cow::Borrowed("ID")]
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

impl Tabled for crate::conntrack::v1::Connection {
    const LENGTH: usize = 3;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        let source = format!("{}:{}", self.src_ip, self.src_port);
        let destination = format!("{}:{}", self.dst_ip, self.dst_port);

        vec![
            Cow::Owned(source),
            Cow::Owned(destination),
            Cow::Borrowed(&self.proto),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            Cow::Borrowed("SOURCE"),
            Cow::Borrowed("DESTINATION"),
            Cow::Borrowed("PROTO"),
        ]
    }
}

impl Tabled for crate::policy::v1::PolicySet {
    const LENGTH: usize = 5;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        vec![
            Cow::Owned(self.src_id.to_string()),
            Cow::Owned(self.dst_id.to_string()),
            Cow::Owned(self.dst_port.to_string()),
            Cow::Borrowed(&self.proto),
            Cow::Borrowed(&self.action),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            Cow::Borrowed("SOURCE ID"),
            Cow::Borrowed("DESTINATION ID"),
            Cow::Borrowed("DESTINATION PORT"),
            Cow::Borrowed("PROTO"),
            Cow::Borrowed("ACTION"),
        ]
    }
}
