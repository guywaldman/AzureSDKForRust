use azure_sdk_auth_aad::authorize_non_interactive;
use azure_sdk_auth_aad::LoginResponse;
use azure_sdk_core::errors::AzureError;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use getset::Getters;
use hyper::{self, header};
use hyper_rustls::HttpsConnector;
use oauth2::{ClientId, ClientSecret};
use serde::Deserialize;
use std::error::Error;
use std::sync::Arc;
use url::Url;

type HttpClient = hyper::Client<HttpsConnector<hyper::client::HttpConnector>>;

quick_error! {
    #[derive(Debug)]
    pub enum KeyVaultError {
        UrlParseError(err: url::ParseError) {
            description("Failed to parse URL correctly")
            from()
            cause(err)
        }
        KeyVaultNotFound(name: String) {
            display("Key Vault '{0}' not found, or is unreachable at '{0}'.value.azure.net", name)
        }
        SecretNotFound(keyvault_name: String, secret_name: String, secret_version: Option<String>) {
            display("Key vault '{}' at version '{}' not found in Key Vault '{}'",
            secret_name,
            match secret_version { Some(s) => s, None => "latest" },
            keyvault_name
        )
        }
        KeyVaultAccess(name: String) {
            display("Error accessing Key Vault '{0}'", name)
        }
        AzureError(err: AzureError) {
            from()
            cause(err)
        }
        RequestError(err: reqwest::Error) {
            from()
            cause(err)
        }
    }
}

#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct KeyVaultSecret {
    name: String,
    version: Option<String>,
    value: String,
    enabled: bool,
    time_created: DateTime<Utc>,
    time_updated: DateTime<Utc>,
}

#[derive(Debug)]
pub struct KeyVaultClient<'a> {
    client_id: ClientId,
    client_secret: ClientSecret,
    tenant_id: &'a str,
    keyvault_name: &'a str,
    http_client: HttpClient,
}

// "value": "mysecretvalue",
//   "id": "https://kv-sdk-test.vault-int.azure-int.net/secrets/mysecretname/4387e9f3d6e14c459867679a90fd0f79",
//   "attributes": {
//     "enabled": true,
//     "created": 1493938410,
//     "updated": 1493938410,
//     "recoveryLevel": "Recoverable+Purgeable"
//   }

#[derive(Deserialize, Debug)]
pub(crate) struct GetSecretResponseAttributes {
    enabled: bool,
    #[serde(with = "ts_seconds")]
    created: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    updated: DateTime<Utc>,
    #[serde(rename = "recoveryLevel")]
    recovery_level: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetSecretResponse {
    value: String,
    id: String,
    attributes: GetSecretResponseAttributes,
}

#[derive(Deserialize, Debug)]
struct KeyVaultErrorReponse {
    code: String,
    message: String,
}

impl<'a> KeyVaultClient<'a> {
    pub fn new(
        client_id: &'a str,
        client_secret: &'a str,
        tenant_id: &'a str,
        keyvault_name: &'a str,
    ) -> Self {
        let http_client = hyper::Client::builder().build(HttpsConnector::new());
        let client_id = ClientId::new(client_id.to_owned());
        let client_secret = ClientSecret::new(client_secret.to_owned());

        Self {
            client_id,
            client_secret,
            tenant_id,
            http_client,
            keyvault_name,
        }
    }

    // TODO: Use AzureError
    // TODO: Use secret_version
    // TODO: Document with REST API link:
    //       https://docs.microsoft.com/en-us/rest/api/keyvault/getsecret/getsecret
    pub async fn get_secret(
        &self,
        secret_name: &'a str,
        secret_version: Option<&'a str>,
    ) -> Result<KeyVaultSecret, Box<dyn Error>> {
        log::info!(
            "Retrieving secret '{}' at version '{}' from the Key Vault '{}'...",
            secret_name,
            secret_version.unwrap_or("latest"),
            self.keyvault_name
        );
        let url = Url::parse(&format!(
            "https://{}.vault.azure.net/secrets/{}/{}?api-version=7.0",
            self.keyvault_name,
            secret_name,
            secret_version.unwrap_or_else(|| &"")
        ))?;

        let token = self.get_authorization_token().await?;

        let request = hyper::Request::get(url.to_string())
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", token.access_token().secret()),
            )
            .body(hyper::Body::empty())?;

        let response = self.http_client.request(request).await;

        let response = match response {
            Ok(resp) if resp.status().as_u16() == 404 => {
                return Err(Box::new(KeyVaultError::SecretNotFound(
                    self.keyvault_name.to_owned(),
                    secret_name.to_owned(),
                    secret_version.map(|s| s.to_owned()),
                )))
            }
            Err(err) if err.is_connect() => {
                return Err(Box::new(KeyVaultError::KeyVaultNotFound(
                    self.keyvault_name.to_owned(),
                )))
            }
            Err(_) => {
                let body = hyper::body::to_bytes(response.unwrap().into_body()).await?;
                let body = std::str::from_utf8(&body).unwrap();
                return Err(Box::new(KeyVaultError::KeyVaultAccess(body.to_owned())));
            }
            Ok(resp) => resp,
        };

        let body = hyper::body::to_bytes(response.into_body()).await?;
        let body = std::str::from_utf8(&body).unwrap();
        let response = serde_json::from_str::<GetSecretResponse>(&body).unwrap();
        let attributes = response.attributes;

        Ok(KeyVaultSecret {
            name: secret_name.to_owned(),
            value: response.value,
            version: secret_version.map(|s| s.to_owned()),
            enabled: attributes.enabled,
            time_created: attributes.created,
            time_updated: attributes.updated,
        })
    }

    async fn get_authorization_token(&self) -> Result<LoginResponse, AzureError> {
        let token = authorize_non_interactive(
            Arc::new(reqwest::Client::new()),
            &self.client_id,
            &self.client_secret,
            "https://vault.azure.net",
            &self.tenant_id,
        )
        .await?;
        Ok(token)
    }
}
