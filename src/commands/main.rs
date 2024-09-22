use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, LabeledError, Signature, Value};

use crate::HmacPlugin;

pub struct Main;

impl SimplePluginCommand for Main {
    type Plugin = HmacPlugin;

    fn name(&self) -> &str {
        "hmac"
    }

    fn description(&self) -> &str {
        "HMAC commands implementing various hash functions"
    }

    fn signature(&self) -> Signature {
        // TODO: choose better category
        Signature::build(self.name()).category(Category::Experimental)
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: &Value,
    ) -> Result<Value, LabeledError> {
        Ok(Value::string(engine.get_help()?, call.head))
    }
}
