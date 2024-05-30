use nu_plugin::{serve_plugin, MsgPackSerializer, Plugin};

mod commands;
use commands::*;

pub struct HmacPlugin;

impl Plugin for HmacPlugin {
    fn commands(&self) -> Vec<Box<dyn nu_plugin::PluginCommand<Plugin = Self>>> {
        vec![
            Box::new(Main),
            Box::new(Sha256),
            Box::new(Sha512),
            Box::new(Whirlpool),
        ]
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }
}

fn main() {
    serve_plugin(&HmacPlugin {}, MsgPackSerializer {});
}
