use anyhow::{Context, Result};
use openapiv3::OpenAPI;
use std::fs;
use std::path::Path;

pub struct OpenApiSpecs {
    pub ue_authentication: OpenAPI,
    pub sor_protection: OpenAPI,
    pub upu_protection: OpenAPI,
}

impl OpenApiSpecs {
    pub fn load() -> Result<Self> {
        let base_path = Path::new("context/3gpp");

        let ue_authentication = Self::load_spec(
            &base_path.join("TS29509_Nausf_UEAuthentication.yaml"),
            "UEAuthentication",
        )?;

        let sor_protection = Self::load_spec(
            &base_path.join("TS29509_Nausf_SoRProtection.yaml"),
            "SoRProtection",
        )?;

        let upu_protection = Self::load_spec(
            &base_path.join("TS29509_Nausf_UPUProtection.yaml"),
            "UPUProtection",
        )?;

        Ok(Self {
            ue_authentication,
            sor_protection,
            upu_protection,
        })
    }

    fn load_spec(path: &Path, service_name: &str) -> Result<OpenAPI> {
        let yaml_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {} OpenAPI spec from {:?}", service_name, path))?;

        let spec: OpenAPI = serde_yaml::from_str(&yaml_content)
            .with_context(|| format!("Failed to parse {} OpenAPI spec", service_name))?;

        tracing::info!(
            service = service_name,
            path = ?path,
            "Loaded OpenAPI specification"
        );

        Ok(spec)
    }
}
