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
