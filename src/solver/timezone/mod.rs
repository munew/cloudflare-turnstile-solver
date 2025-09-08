use anyhow::Context;
use maxminddb::Reader;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::net::IpAddr;

static MAXMIND_READER: Lazy<Reader<Vec<u8>>> =
    Lazy::new(|| Reader::from_source(include_bytes!("GeoLite2-City.mmdb").to_vec()).unwrap());

#[derive(Debug, Deserialize)]
struct City {
    location: Option<Location>,
}

#[derive(Debug, Deserialize)]
struct Location {
    time_zone: Option<String>,
}

pub fn get_timezone(ip: &str) -> Result<String, anyhow::Error> {
    let ip: IpAddr = ip.parse()?;
    let city: City = MAXMIND_READER.lookup(ip)?.context("ip is not in db")?;

    if let Some(location) = city.location
        && let Some(time_zone) = location.time_zone
    {
        return Ok(time_zone);
    }

    Err(anyhow::anyhow!("could not find location for ip"))
}
