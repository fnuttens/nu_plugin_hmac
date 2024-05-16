use hmac::{Hmac, Mac};
use nu_plugin::{
    serve_plugin, EngineInterface, EvaluatedCall, MsgPackSerializer, Plugin, SimplePluginCommand,
};
use nu_protocol::{Category, Example, LabeledError, Signature, SyntaxShape, Type, Value};

struct HmacPlugin;

impl Plugin for HmacPlugin {
    fn commands(&self) -> Vec<Box<dyn nu_plugin::PluginCommand<Plugin = Self>>> {
        vec![Box::new(Main), Box::new(Sha256), Box::new(Sha512)]
    }
}

fn main() {
    serve_plugin(&HmacPlugin {}, MsgPackSerializer {});
}

// TODO: put in own module
struct Main;
struct Sha256;
struct Sha512;

impl SimplePluginCommand for Main {
    type Plugin = HmacPlugin;

    fn name(&self) -> &str {
        "hmac"
    }

    fn usage(&self) -> &str {
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

impl SimplePluginCommand for Sha256 {
    type Plugin = HmacPlugin;

    fn name(&self) -> &str {
        "hmac sha256"
    }

    fn usage(&self) -> &str {
        "HMAC-SHA256 sealing"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            // TODO: choose better category
            .category(Category::Experimental)
            .input_output_type(Type::String, Type::String)
            .required("secret", SyntaxShape::String, "Secret key to use")
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
        let message = input.as_str()?;
        let secret = call.req::<Vec<u8>>(0)?;

        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret)
            .map_err(|_| LabeledError::new("Invalid key length"))?;
        mac.update(message.as_bytes());

        let result = mac.finalize().into_bytes();
        Ok(Value::string(hex::encode(result), call.head))
    }
}

impl SimplePluginCommand for Sha512 {
    type Plugin = HmacPlugin;

    fn name(&self) -> &str {
        "hmac sha512"
    }

    fn usage(&self) -> &str {
        "HMAC-SHA512 sealing"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(self.name())
            // TODO: choose better category
            .category(Category::Experimental)
            .input_output_type(Type::String, Type::String)
            .required("secret", SyntaxShape::String, "Secret key to use")
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["hmac", "sha", "sha-2", "sha512"]
    }

    fn examples(&self) -> Vec<nu_protocol::Example> {
        vec![Example {
            example: "\"foobar\" | hmac sha512 \"my_secret\"",
            description: "seal “foobar” message using “my_secret” key",
            result: Some(Value::test_string(
                "6b46bb83bd0f2f721c7b7b8c9ea4904ca43bc792ea2991ac11c3d33d1e44381c2a60df3776e965d9fdc9761b901d2ea7cb3d407a0e3ecb650088127743314ee5",
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
        let message = input.as_str()?;
        let secret = call.req::<Vec<u8>>(0)?;

        let mut mac = Hmac::<sha2::Sha512>::new_from_slice(&secret)
            .map_err(|_| LabeledError::new("Invalid key length"))?;
        mac.update(message.as_bytes());

        let result = mac.finalize().into_bytes();
        Ok(Value::string(hex::encode(result), call.head))
    }
}

#[test]
fn test_examples() -> Result<(), nu_protocol::ShellError> {
    use nu_plugin_test_support::PluginTest;
    PluginTest::new("sha256", HmacPlugin.into())?.test_command_examples(&Sha256)?;
    PluginTest::new("sha512", HmacPlugin.into())?.test_command_examples(&Sha512)
}
