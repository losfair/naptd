#[macro_use]
extern crate serde_derive;

mod config;
mod tun;

use std::fs::File;
use std::io::Read;
use std::convert::TryFrom;
use std::sync::Arc;
use crate::config::{InConfig, Config};
use crate::tun::Tun;

fn main() {
    let config_path = std::env::args().nth(1).expect("path to configuration file required");
    let mut config = String::new();
    File::open(&config_path).expect("cannot open configuration file")
        .read_to_string(&mut config).expect("cannot read configuration file");
    let config: InConfig = serde_json::from_str(&config).expect("cannot parse configuration file");
    let config = Config::try_from(config).expect("cannot generate configuration object");
    let mut tun = Tun::new_leaking_name(Arc::new(config)).expect("cannot create tunnel");
    tun.run();
    panic!("tunnel unexpectedly terminated");
}
