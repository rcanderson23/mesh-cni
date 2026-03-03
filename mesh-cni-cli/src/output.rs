use serde::Serialize;
use tabled::{Table, Tabled, settings::Style};

use crate::cli::OutputFormat;

pub(crate) fn print<T>(items: Vec<T>, output: OutputFormat) -> anyhow::Result<()>
where
    T: Tabled + Serialize,
{
    match output {
        OutputFormat::Table => {
            let table = Table::new(items).with(Style::empty()).to_string();
            println!("{table}");
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&items)?;
            println!("{json}");
        }
    }
    Ok(())
}
