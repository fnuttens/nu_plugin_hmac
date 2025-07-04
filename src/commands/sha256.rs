use hmac::{Hmac, Mac};
use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, Example, LabeledError, Signature, SyntaxShape, Type, Value};

use crate::HmacPlugin;

pub struct Sha256;

impl SimplePluginCommand for Sha256 {
    type Plugin = HmacPlugin;

    fn name(&self) -> &str {
        "hmac sha256"
    }

    fn description(&self) -> &str {
        "HMAC-SHA256 sealing"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            .category(Category::Hash)
            .input_output_types(vec![
                (Type::String, Type::String),
                (Type::Binary, Type::String),
            ])
            .required(
                "secret",
                SyntaxShape::OneOf(vec![SyntaxShape::String, SyntaxShape::Binary]),
                "Secret key to use",
            )
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["hmac", "sha", "sha-2", "sha256"]
    }

    fn examples(&self) -> Vec<nu_protocol::Example> {
        vec![Example {
            example: "\"foobar\" | hmac sha256 \"my_secret\"",
            description: "seal “foobar” message using “my_secret” key",
            result: Some(Value::test_string(
                "c95f4062da9dd9474896abd3a0577f7e4493a09fe033a7393e539481062dca07",
            )),
        }]
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, LabeledError> {
        let message = input.coerce_binary()?;
        let secret = call.req::<Vec<u8>>(0)?;

        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret)
            .map_err(|_| LabeledError::new("Invalid key length"))?;
        mac.update(message);

        let result = mac.finalize().into_bytes();
        Ok(Value::string(hex::encode(result), call.head))
    }
}

#[test]
fn test_examples() -> Result<(), nu_protocol::ShellError> {
    use nu_plugin_test_support::PluginTest;
    PluginTest::new("sha256", HmacPlugin.into())?.test_command_examples(&Sha256)
}
