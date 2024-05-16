use hmac::{Hmac, Mac};
use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, Example, LabeledError, Signature, SyntaxShape, Type, Value};

use crate::HmacPlugin;

pub struct Whirlpool;

impl SimplePluginCommand for Whirlpool {
    type Plugin = HmacPlugin;

    fn name(&self) -> &str {
        "hmac whirlpool"
    }

    fn usage(&self) -> &str {
        "HMAC-WHIRLPOOL sealing"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            .category(Category::Experimental)
            .input_output_type(Type::String, Type::String)
            .required("secret", SyntaxShape::String, "Secret key to use")
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["hmac", "whirlpool"]
    }

    fn examples(&self) -> Vec<nu_protocol::Example> {
        vec![Example {
            example: "\"foobar\" | hmac whirlpool \"my_secret\"",
            description: "seal “foobar” message using “my_secret” key",
            result: Some(Value::test_string("280dc5dc3bd6c90caccca01d60d303664439a551002d3dbe53cb32da368118c70fab044775391c4526de0ef7a07f19d97eeca1d84dafd96d5b85e84b22b4e96f")),
        }]
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, nu_protocol::LabeledError> {
        let message = input.as_str()?;
        let secret = call.req::<Vec<u8>>(0)?;

        let mut mac = Hmac::<whirlpool::Whirlpool>::new_from_slice(&secret)
            .map_err(|_| LabeledError::new("Invalid key length"))?;
        mac.update(message.as_bytes());

        let result = mac.finalize().into_bytes();
        Ok(Value::string(hex::encode(result), call.head))
    }
}

#[test]
fn test_examples() -> Result<(), nu_protocol::ShellError> {
    use nu_plugin_test_support::PluginTest;
    PluginTest::new("whirlpool", HmacPlugin.into())?.test_command_examples(&Whirlpool)
}
