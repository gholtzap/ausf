use crate::types::udm::AuthenticationVector;

pub type ValidationResult<T> = Result<T, ValidationError>;

#[derive(Debug)]
pub enum ValidationError {
    InvalidRandLength { expected: usize, actual: usize },
    InvalidXresStarLength { min: usize, max: usize, actual: usize },
    InvalidAutnLength { expected: usize, actual: usize },
    InvalidKausfLength { expected: usize, actual: usize },
    InvalidHexEncoding(String),
    MissingField(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidRandLength { expected, actual } => {
                write!(f, "Invalid RAND length: expected {} hex chars, got {}", expected, actual)
            }
            ValidationError::InvalidXresStarLength { min, max, actual } => {
                write!(f, "Invalid XRES* length: expected {}-{} hex chars, got {}", min, max, actual)
            }
            ValidationError::InvalidAutnLength { expected, actual } => {
                write!(f, "Invalid AUTN length: expected {} hex chars, got {}", expected, actual)
            }
            ValidationError::InvalidKausfLength { expected, actual } => {
                write!(f, "Invalid KAUSF length: expected {} hex chars, got {}", expected, actual)
            }
            ValidationError::InvalidHexEncoding(field) => {
                write!(f, "Invalid hex encoding in field: {}", field)
            }
            ValidationError::MissingField(field) => {
                write!(f, "Missing required field: {}", field)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_authentication_vector(av: &AuthenticationVector) -> ValidationResult<()> {
    match av {
        AuthenticationVector::Av5gAka(av_5g) => {
            validate_hex(&av_5g.rand, "rand")?;
            validate_hex(&av_5g.xres_star, "xres_star")?;
            validate_hex(&av_5g.autn, "autn")?;
            validate_hex(&av_5g.kausf, "kausf")?;

            if av_5g.rand.len() != 32 {
                return Err(ValidationError::InvalidRandLength {
                    expected: 32,
                    actual: av_5g.rand.len(),
                });
            }

            if av_5g.xres_star.len() < 8 || av_5g.xres_star.len() > 32 {
                return Err(ValidationError::InvalidXresStarLength {
                    min: 8,
                    max: 32,
                    actual: av_5g.xres_star.len(),
                });
            }

            if av_5g.autn.len() != 32 {
                return Err(ValidationError::InvalidAutnLength {
                    expected: 32,
                    actual: av_5g.autn.len(),
                });
            }

            if av_5g.kausf.len() != 64 {
                return Err(ValidationError::InvalidKausfLength {
                    expected: 64,
                    actual: av_5g.kausf.len(),
                });
            }

            Ok(())
        }
        AuthenticationVector::AvEapAkaPrime(av_eap) => {
            validate_hex(&av_eap.rand, "rand")?;
            validate_hex(&av_eap.xres, "xres")?;
            validate_hex(&av_eap.autn, "autn")?;

            if av_eap.rand.len() != 32 {
                return Err(ValidationError::InvalidRandLength {
                    expected: 32,
                    actual: av_eap.rand.len(),
                });
            }

            if av_eap.xres.len() < 8 || av_eap.xres.len() > 32 {
                return Err(ValidationError::InvalidXresStarLength {
                    min: 8,
                    max: 32,
                    actual: av_eap.xres.len(),
                });
            }

            if av_eap.autn.len() != 32 {
                return Err(ValidationError::InvalidAutnLength {
                    expected: 32,
                    actual: av_eap.autn.len(),
                });
            }

            Ok(())
        }
    }
}

fn validate_hex(value: &str, field_name: &str) -> ValidationResult<()> {
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHexEncoding(field_name.to_string()));
    }
    Ok(())
}
