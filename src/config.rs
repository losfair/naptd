use std::net::Ipv6Addr;
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InConfig {
    pub left: String,
    pub right: String,
    pub iface_name: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub left: Ipv6Addr,
    pub right: Ipv6Addr,
    pub iface_name: String,
}

impl TryFrom<InConfig> for Config {
    type Error = String;

    fn try_from(x: InConfig) -> Result<Self, String> {
        Ok(Config {
            left: x.left.parse().map_err(|_| "invalid left prefix".to_string())?,
            right: x.right.parse().map_err(|_| "invalid right prefix".to_string())?,
            iface_name: x.iface_name,
        })
    }
}
