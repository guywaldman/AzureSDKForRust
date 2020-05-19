use azure_sdk_keyvault::prelude::*;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let client_id = "2de21349-435d-454d-aa3c-3437b7c8fe1f";
    let client_secret = ".5E0XPY3FhGq-X4IM92Q~Q5QWR~Ln2-Fc0";
    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let keyvault_name = "guywald-personal";

    let client = KeyVaultClient::new(client_id, client_secret, tenant_id, keyvault_name);
    let secret = client.get_secret("test", None).await?;
    client.set_secret("foo1", "bar1").await?;
    Ok(())
}
