use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, Method, HeaderMap},
    middleware::Next,
    response::Response,
};
use openapiv3::{OpenAPI, Operation, PathItem, ReferenceOr, RequestBody, MediaType};
use jsonschema::JSONSchema;
use serde_json::Value;
use std::collections::HashMap;
use crate::types::{AppState, ProblemDetails, InvalidParam};

pub async fn validate_request(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<ProblemDetails>)> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let spec = determine_spec(&state, &path)?;

    let (operation, path_params) = match find_operation(spec, &path, &method) {
        Some((op, params)) => (op, params),
        None => {
            return Ok(next.run(req).await);
        }
    };

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                axum::Json(ProblemDetails {
                    r#type: Some("https://example.com/validation-error".to_string()),
                    title: Some("Request Body Read Error".to_string()),
                    status: Some(400),
                    detail: Some(format!("Failed to read request body: {}", e)),
                    instance: None,
                    cause: None,
                    invalid_params: None,
                    supported_features: None,
                }),
            )
        })?;

    let body_json: Option<Value> = if !body_bytes.is_empty() {
        Some(serde_json::from_slice(&body_bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                axum::Json(ProblemDetails {
                    r#type: Some("https://example.com/validation-error".to_string()),
                    title: Some("Invalid JSON".to_string()),
                    status: Some(400),
                    detail: Some(format!("Request body is not valid JSON: {}", e)),
                    instance: None,
                    cause: None,
                    invalid_params: None,
                    supported_features: None,
                }),
            )
        })?)
    } else {
        None
    };

    let mut invalid_params = Vec::new();

    if let Some(request_body) = &operation.request_body {
        validate_request_body(request_body, &body_json, &mut invalid_params)?;
    }

    if !operation.parameters.is_empty() {
        validate_parameters(spec, &operation.parameters, &parts, &path_params, &mut invalid_params)?;
    }

    if !invalid_params.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ProblemDetails {
                r#type: Some("https://example.com/validation-error".to_string()),
                title: Some("Validation Error".to_string()),
                status: Some(400),
                detail: Some("Request validation failed".to_string()),
                instance: None,
                cause: None,
                invalid_params: Some(invalid_params),
                supported_features: None,
            }),
        ));
    }

    let req = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(req).await)
}

pub async fn validate_response(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = next.run(req).await;

    let spec = match determine_spec_no_error(&state, &path) {
        Some(s) => s,
        None => return response,
    };

    let (operation, _) = match find_operation(spec, &path, &method) {
        Some((op, params)) => (op, params),
        None => return response,
    };

    let (parts, body) = response.into_parts();
    let status = parts.status;

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to read response body for validation: {}", e);
            return Response::from_parts(parts, Body::default());
        }
    };

    let body_json: Option<Value> = if !body_bytes.is_empty() {
        match serde_json::from_slice(&body_bytes) {
            Ok(json) => Some(json),
            Err(_) => None,
        }
    } else {
        None
    };

    validate_response_against_spec(operation, status, &body_json, &parts.headers);

    Response::from_parts(parts, Body::from(body_bytes))
}

fn determine_spec_no_error<'a>(state: &'a AppState, path: &str) -> Option<&'a OpenAPI> {
    if path.starts_with("/nausf-auth/") || path.starts_with("/ue-authentications") {
        Some(&state.openapi_specs.ue_authentication)
    } else if path.starts_with("/nausf-sorprotection/") {
        Some(&state.openapi_specs.sor_protection)
    } else if path.starts_with("/nausf-upuprotection/") {
        Some(&state.openapi_specs.upu_protection)
    } else {
        None
    }
}

fn validate_response_against_spec(
    operation: &Operation,
    status: StatusCode,
    body_json: &Option<Value>,
    headers: &HeaderMap,
) {
    let status_str = status.as_u16().to_string();
    let default_status = "default".to_string();

    let response_spec = operation.responses.responses.get(&openapiv3::StatusCode::Code(status.as_u16()))
        .or_else(|| operation.responses.responses.get(&openapiv3::StatusCode::Range(status.as_u16() / 100)))
        .or_else(|| operation.responses.default.as_ref().map(|r| r));

    if response_spec.is_none() {
        tracing::warn!(
            "Response status {} not defined in OpenAPI spec for operation",
            status
        );
        return;
    }

    let response_spec = response_spec.unwrap();
    let response = match response_spec {
        ReferenceOr::Reference { .. } => {
            tracing::debug!("Response is a reference, skipping validation");
            return;
        }
        ReferenceOr::Item(r) => r,
    };

    if let Some(json) = body_json {
        if let Some(content) = &response.content.get("application/json") {
            if let Some(schema_ref) = &content.schema {
                let schema = match schema_ref {
                    ReferenceOr::Reference { .. } => {
                        tracing::debug!("Response schema is a reference, skipping validation");
                        return;
                    }
                    ReferenceOr::Item(s) => s,
                };

                let schema_json = schema_to_json(&schema.schema_kind);

                match JSONSchema::options().compile(&schema_json) {
                    Ok(compiled) => {
                        if let Err(errors) = compiled.validate(json) {
                            let error_messages: Vec<String> = errors
                                .map(|e| format!("{} at {}", e, e.instance_path))
                                .collect();
                            tracing::warn!(
                                "Response body validation failed: {}",
                                error_messages.join(", ")
                            );
                        } else {
                            tracing::debug!("Response body validation passed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to compile response schema: {}", e);
                    }
                }
            }
        }
    }

    if !response.headers.is_empty() {
        for (header_name, header_spec) in &response.headers {
            let header_value = headers.get(header_name.as_str());

            let header_def = match header_spec {
                ReferenceOr::Reference { .. } => continue,
                ReferenceOr::Item(h) => h,
            };

            if header_def.required && header_value.is_none() {
                tracing::warn!(
                    "Required response header '{}' is missing",
                    header_name
                );
            }
        }
    }
}

fn determine_spec<'a>(state: &'a AppState, path: &str) -> Result<&'a OpenAPI, (StatusCode, axum::Json<ProblemDetails>)> {
    if path.starts_with("/nausf-auth/") || path.starts_with("/ue-authentications") {
        Ok(&state.openapi_specs.ue_authentication)
    } else if path.starts_with("/nausf-sorprotection/") {
        Ok(&state.openapi_specs.sor_protection)
    } else if path.starts_with("/nausf-upuprotection/") {
        Ok(&state.openapi_specs.upu_protection)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            axum::Json(ProblemDetails {
                r#type: Some("https://example.com/not-found".to_string()),
                title: Some("Not Found".to_string()),
                status: Some(404),
                detail: Some("No matching OpenAPI specification found for this path".to_string()),
                instance: None,
                cause: None,
                invalid_params: None,
                supported_features: None,
            }),
        ))
    }
}

fn find_operation<'a>(
    spec: &'a OpenAPI,
    path: &str,
    method: &Method,
) -> Option<(&'a Operation, HashMap<String, String>)> {
    for (path_pattern, path_item) in &spec.paths.paths {
        if let Some(params) = match_path(path_pattern, path) {
            let path_item_resolved = match path_item {
                ReferenceOr::Reference { .. } => continue,
                ReferenceOr::Item(item) => item,
            };

            let operation = match_method(path_item_resolved, method);
            if let Some(op) = operation {
                return Some((op, params));
            }
        }
    }
    None
}

fn match_path(pattern: &str, path: &str) -> Option<HashMap<String, String>> {
    let pattern_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();

    if pattern_parts.len() != path_parts.len() {
        return None;
    }

    let mut params = HashMap::new();

    for (pattern_part, path_part) in pattern_parts.iter().zip(path_parts.iter()) {
        if pattern_part.starts_with('{') && pattern_part.ends_with('}') {
            let param_name = &pattern_part[1..pattern_part.len() - 1];
            params.insert(param_name.to_string(), path_part.to_string());
        } else if pattern_part != path_part {
            return None;
        }
    }

    Some(params)
}

fn match_method<'a>(path_item: &'a PathItem, method: &Method) -> Option<&'a Operation> {
    match method {
        &Method::GET => path_item.get.as_ref(),
        &Method::POST => path_item.post.as_ref(),
        &Method::PUT => path_item.put.as_ref(),
        &Method::DELETE => path_item.delete.as_ref(),
        &Method::PATCH => path_item.patch.as_ref(),
        &Method::OPTIONS => path_item.options.as_ref(),
        &Method::HEAD => path_item.head.as_ref(),
        &Method::TRACE => path_item.trace.as_ref(),
        _ => None,
    }
}

fn validate_request_body(
    request_body: &ReferenceOr<RequestBody>,
    body_json: &Option<Value>,
    invalid_params: &mut Vec<InvalidParam>,
) -> Result<(), (StatusCode, axum::Json<ProblemDetails>)> {
    let request_body_resolved = match request_body {
        ReferenceOr::Reference { .. } => {
            return Ok(());
        }
        ReferenceOr::Item(rb) => rb,
    };

    if request_body_resolved.required && body_json.is_none() {
        invalid_params.push(InvalidParam {
            param: "body".to_string(),
            reason: Some("Request body is required but not provided".to_string()),
        });
        return Ok(());
    }

    if let Some(body) = body_json {
        if let Some(content) = &request_body_resolved.content.get("application/json") {
            validate_media_type(content, body, "body", invalid_params)?;
        }
    }

    Ok(())
}

fn validate_media_type(
    media_type: &MediaType,
    value: &Value,
    param_name: &str,
    invalid_params: &mut Vec<InvalidParam>,
) -> Result<(), (StatusCode, axum::Json<ProblemDetails>)> {
    if let Some(schema_ref) = &media_type.schema {
        let schema = match schema_ref {
            ReferenceOr::Reference { .. } => {
                return Ok(());
            }
            ReferenceOr::Item(s) => s,
        };

        let schema_json = schema_to_json(&schema.schema_kind);

        match JSONSchema::options().compile(&schema_json) {
            Ok(compiled) => {
                if let Err(errors) = compiled.validate(value) {
                    for error in errors {
                        invalid_params.push(InvalidParam {
                            param: format!("{}.{}", param_name, error.instance_path),
                            reason: Some(error.to_string()),
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to compile JSON schema: {}", e);
            }
        }
    }

    Ok(())
}

fn validate_parameters(
    spec: &OpenAPI,
    parameters: &[ReferenceOr<openapiv3::Parameter>],
    parts: &axum::http::request::Parts,
    path_params: &HashMap<String, String>,
    invalid_params: &mut Vec<InvalidParam>,
) -> Result<(), (StatusCode, axum::Json<ProblemDetails>)> {
    for param_ref in parameters {
        let param = match param_ref {
            ReferenceOr::Reference { reference } => {
                match resolve_parameter_reference(spec, reference) {
                    Some(p) => p,
                    None => continue,
                }
            }
            ReferenceOr::Item(p) => p,
        };

        match param {
            openapiv3::Parameter::Path { parameter_data, .. } => {
                validate_path_parameter(parameter_data, path_params, invalid_params);
            }
            openapiv3::Parameter::Query { parameter_data, .. } => {
                validate_query_parameter(parameter_data, parts, invalid_params);
            }
            openapiv3::Parameter::Header { parameter_data, .. } => {
                validate_header_parameter(parameter_data, parts, invalid_params);
            }
            openapiv3::Parameter::Cookie { .. } => {}
        }
    }

    Ok(())
}

fn resolve_parameter_reference<'a>(
    spec: &'a OpenAPI,
    reference: &str,
) -> Option<&'a openapiv3::Parameter> {
    let ref_path = reference.trim_start_matches("#/components/parameters/");
    spec.components.as_ref()?.parameters.get(ref_path).and_then(|r| match r {
        ReferenceOr::Item(p) => Some(p),
        ReferenceOr::Reference { .. } => None,
    })
}

fn validate_path_parameter(
    parameter_data: &openapiv3::ParameterData,
    path_params: &HashMap<String, String>,
    invalid_params: &mut Vec<InvalidParam>,
) {
    let value = path_params.get(&parameter_data.name);

    if parameter_data.required && value.is_none() {
        invalid_params.push(InvalidParam {
            param: parameter_data.name.clone(),
            reason: Some("Required path parameter is missing".to_string()),
        });
    }
}

fn validate_query_parameter(
    parameter_data: &openapiv3::ParameterData,
    parts: &axum::http::request::Parts,
    invalid_params: &mut Vec<InvalidParam>,
) {
    let query = parts.uri.query().unwrap_or("");
    let query_params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    let value = query_params.get(&parameter_data.name);

    if parameter_data.required && value.is_none() {
        invalid_params.push(InvalidParam {
            param: parameter_data.name.clone(),
            reason: Some("Required query parameter is missing".to_string()),
        });
    }
}

fn validate_header_parameter(
    parameter_data: &openapiv3::ParameterData,
    parts: &axum::http::request::Parts,
    invalid_params: &mut Vec<InvalidParam>,
) {
    let header_name = parameter_data.name.to_lowercase();
    let value = parts.headers.get(&header_name);

    if parameter_data.required && value.is_none() {
        invalid_params.push(InvalidParam {
            param: parameter_data.name.clone(),
            reason: Some("Required header is missing".to_string()),
        });
    }
}

fn schema_to_json(schema: &openapiv3::SchemaKind) -> Value {
    match schema {
        openapiv3::SchemaKind::Type(t) => type_to_json(t),
        openapiv3::SchemaKind::OneOf { .. } => serde_json::json!({}),
        openapiv3::SchemaKind::AllOf { .. } => serde_json::json!({}),
        openapiv3::SchemaKind::AnyOf { .. } => serde_json::json!({}),
        openapiv3::SchemaKind::Not { .. } => serde_json::json!({}),
        openapiv3::SchemaKind::Any(_) => serde_json::json!({}),
    }
}

fn type_to_json(type_def: &openapiv3::Type) -> Value {
    match type_def {
        openapiv3::Type::String(s) => {
            let mut schema = serde_json::json!({
                "type": "string"
            });
            match &s.format {
                openapiv3::VariantOrUnknownOrEmpty::Item(format) => {
                    let format_str = match format {
                        openapiv3::StringFormat::Date => "date",
                        openapiv3::StringFormat::DateTime => "date-time",
                        openapiv3::StringFormat::Password => "password",
                        openapiv3::StringFormat::Byte => "byte",
                        openapiv3::StringFormat::Binary => "binary",
                    };
                    schema["format"] = Value::String(format_str.to_string());
                }
                _ => {}
            }
            if let Some(pattern) = &s.pattern {
                schema["pattern"] = Value::String(pattern.clone());
            }
            if let Some(min) = s.min_length {
                schema["minLength"] = Value::Number(min.into());
            }
            if let Some(max) = s.max_length {
                schema["maxLength"] = Value::Number(max.into());
            }
            schema
        }
        openapiv3::Type::Number(n) => {
            let mut schema = serde_json::json!({
                "type": "number"
            });
            match &n.format {
                openapiv3::VariantOrUnknownOrEmpty::Item(format) => {
                    let format_str = match format {
                        openapiv3::NumberFormat::Float => "float",
                        openapiv3::NumberFormat::Double => "double",
                    };
                    schema["format"] = Value::String(format_str.to_string());
                }
                _ => {}
            }
            if let Some(min) = n.minimum {
                schema["minimum"] = Value::Number(serde_json::Number::from_f64(min).unwrap());
            }
            if let Some(max) = n.maximum {
                schema["maximum"] = Value::Number(serde_json::Number::from_f64(max).unwrap());
            }
            schema
        }
        openapiv3::Type::Integer(i) => {
            let mut schema = serde_json::json!({
                "type": "integer"
            });
            match &i.format {
                openapiv3::VariantOrUnknownOrEmpty::Item(format) => {
                    let format_str = match format {
                        openapiv3::IntegerFormat::Int32 => "int32",
                        openapiv3::IntegerFormat::Int64 => "int64",
                    };
                    schema["format"] = Value::String(format_str.to_string());
                }
                _ => {}
            }
            if let Some(min) = i.minimum {
                schema["minimum"] = Value::Number(min.into());
            }
            if let Some(max) = i.maximum {
                schema["maximum"] = Value::Number(max.into());
            }
            schema
        }
        openapiv3::Type::Object(o) => {
            let mut schema = serde_json::json!({
                "type": "object"
            });

            if !o.properties.is_empty() {
                let mut props = serde_json::Map::new();
                for (name, prop_ref) in &o.properties {
                    if let ReferenceOr::Item(prop) = prop_ref {
                        props.insert(name.clone(), schema_to_json(&prop.schema_kind));
                    }
                }
                schema["properties"] = Value::Object(props);
            }

            if !o.required.is_empty() {
                schema["required"] = Value::Array(
                    o.required.iter().map(|r| Value::String(r.clone())).collect()
                );
            }

            if let Some(additional) = &o.additional_properties {
                match additional {
                    openapiv3::AdditionalProperties::Any(b) => {
                        schema["additionalProperties"] = Value::Bool(*b);
                    }
                    openapiv3::AdditionalProperties::Schema(_) => {
                        schema["additionalProperties"] = Value::Bool(true);
                    }
                }
            }

            schema
        }
        openapiv3::Type::Array(a) => {
            let mut schema = serde_json::json!({
                "type": "array"
            });

            if let Some(items) = &a.items {
                if let ReferenceOr::Item(item_schema) = items.clone().unbox() {
                    schema["items"] = schema_to_json(&item_schema.schema_kind);
                }
            }

            if let Some(min) = a.min_items {
                schema["minItems"] = Value::Number(min.into());
            }
            if let Some(max) = a.max_items {
                schema["maxItems"] = Value::Number(max.into());
            }

            schema
        }
        openapiv3::Type::Boolean(_) => serde_json::json!({
            "type": "boolean"
        }),
    }
}
