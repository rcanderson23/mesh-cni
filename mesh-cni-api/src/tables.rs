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
