use anyhow::{Result, bail, ensure};
use tiny_keccak::Hasher;
use unicode_normalization::UnicodeNormalization;

use crate::json_path;

/// Returns an [NFKD normalized] unicode representation of the input
///
/// [NFKD normalized]: https://en.wikipedia.org/wiki/Unicode_equivalence#Normal_forms
pub fn normalize_unicode(s: &str) -> String {
    s.nfkd().collect()
}

/// Multibase-encoded hash of the provided bytes used in many places around this crate.
///
/// We use SHA3_256 (not Keccak) with Base-64 URL encoding.
pub fn default_hasher(content: &[u8]) -> String {
    // TODO we might want to use sha3 crate instead of tiny_keccak
    let mut hasher = tiny_keccak::Sha3::v256();
    let mut hash_output = [0u8; 32];
    hasher.update(content);
    hasher.finalize(&mut hash_output);
    multibase::encode(multibase::Base::Base64Url, hash_output)
}

/// Multibase-encoded hash of the utf8 representation of the provided string,
/// prefixed with "cj". Character 'j' marks that a JSON value was hashed and
/// 'c' stands for content hash.
fn hash_str(content: &str) -> String {
    format!("cj{}", default_hasher(content.as_bytes()))
}

/// Action to take when walking a JSON tree node.
#[derive(Clone, Copy, Debug, PartialEq)]
enum WalkAction {
    /// Keep the subtree expanded in the output.
    Keep,
    /// Replace the subtree with its content hash.
    Hash,
}

/// Returns `true` when `path` starts with all elements of `prefix` (segment-wise).
fn path_starts_with<P: AsRef<str>, Q: AsRef<str>>(path: &[P], prefix: &[Q]) -> bool {
    path.len() >= prefix.len()
        && path.iter().zip(prefix.iter()).all(|(a, b)| a.as_ref() == b.as_ref())
}

/// Splits a dotted JSON path (`.foo.bar`) into borrowed segments `["foo", "bar"]`.
///
/// Array index notation is expanded: `.foo[0].bar` → `["foo", "[0]", "bar"]`
/// and `.foo[0][1]` → `["foo", "[0]", "[1]"]`.
fn split_path(path: &str) -> Result<Vec<&str>> {
    if !path.starts_with('.') {
        bail!("Path must start with '.' but it's: {path}");
    }
    let inner = &path[1..];
    let mut segments = Vec::new();

    for dot_seg in inner.split('.') {
        let mut rest = dot_seg;
        while let Some(bracket_pos) = rest.find('[') {
            if bracket_pos > 0 {
                segments.push(&rest[..bracket_pos]);
            }
            let close = rest[bracket_pos..]
                .find(']')
                .ok_or_else(|| anyhow::anyhow!("Unclosed bracket in path: {path}"))?;
            segments.push(&rest[bracket_pos..bracket_pos + close + 1]);
            rest = &rest[bracket_pos + close + 1..];
        }
        if !rest.is_empty() {
            segments.push(rest);
        }
    }

    Ok(segments)
}

/// Recursively walk a JSON value, producing a deterministic JSON string.
///
/// For every container node (object or array) the `decide` closure is called to
/// determine whether that node should be kept open (canonical JSON) or replaced
/// by its content hash.  Scalars are always rendered in canonical form.
///
/// The `path` argument tracks the current location using object-key strings and
/// array-index `"[N]"` segments so that `decide` can make path-aware decisions.
fn walk_json(
    data: &serde_json::Value, path: &[String],
    decide: &mut dyn FnMut(&[String], &serde_json::Value) -> WalkAction,
) -> Result<String> {
    let result = match data {
        serde_json::Value::Array(arr) => {
            let mut items = Vec::new();
            for (i, item) in arr.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(format!("[{i}]"));
                items.push(walk_json(item, &child_path, decide)?);
            }
            format!("[{}]", items.join(","))
        }

        serde_json::Value::Object(obj) => {
            let mut keys: Vec<_> = obj.keys().collect();
            keys.sort();
            let mut entries = Vec::new();
            for key in keys {
                ensure!(
                    *key == normalize_unicode(key),
                    "Data for canonical JSON serialization must contain field names normalized with Unicode NFKD"
                );

                let canonical_key =
                    walk_json(&serde_json::Value::String(key.to_owned()), &[], &mut |_, _| {
                        WalkAction::Keep
                    })?;
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                let value = obj
                    .get(key)
                    .expect("keys() on serde_json::Map returned a key that is not in the map");
                entries.push(format!(
                    "{}:{}",
                    canonical_key,
                    walk_json(value, &child_path, decide)?
                ));
            }
            format!("{{{}}}", entries.join(","))
        }

        serde_json::Value::Number(n) => canonicalize_number(n),

        _ => {
            let data_str = serde_json::to_string(data)
                .expect("serde_json::to_string infallible for Null/Bool/String values");
            normalize_unicode(&data_str)
        }
    };

    if matches!(data, serde_json::Value::Array(_) | serde_json::Value::Object(_))
        && decide(path, data) == WalkAction::Hash
    {
        Ok(format!("\"{}\"", hash_str(&result)))
    } else {
        Ok(result)
    }
}

fn canonicalize_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().expect("serde_json::Number: i64/u64 rejected, must be f64");

    // Integer-valued floats within i64 range → format as integer (3.0 → 3, 100.0 → 100)
    if f.is_finite() && f.fract() == 0.0 && f >= (i64::MIN as f64) && f <= (i64::MAX as f64) {
        return (f as i64).to_string();
    }

    let s = serde_json::to_string(n).expect("serde_json::Number::to_string infallible");

    if let Some(e_pos) = s.find('e') {
        let mantissa = &s[..e_pos];
        let after_e = &s[e_pos + 1..];
        let (sign, exp_str) = if let Some(stripped) = after_e.strip_prefix('+') {
            ('+', stripped)
        } else if let Some(stripped) = after_e.strip_prefix('-') {
            ('-', stripped)
        } else {
            ('+', after_e) // no sign → positive exponent, add '+'
        };
        let exp: i64 = exp_str.parse().unwrap_or(0);

        // ECMAScript Number::toString: decimal if 10⁻⁶ ≤ |f| < 10²¹
        if (sign == '+' && exp < 21) || (sign == '-' && exp <= 6) {
            return format!("{}", f);
        }
        // Strip trailing zeros from mantissa (handles raw-text "3.0e+30" → "3e+30")
        let mantissa_stripped = mantissa.trim_end_matches('0');
        let mantissa_clean = mantissa_stripped.strip_suffix('.').unwrap_or(mantissa_stripped);
        return format!("{}e{}{}", mantissa_clean, sign, exp_str);
    }

    // No 'e' — format through f64 to strip trailing zeros (handles raw-text preservation
    // for cases like "65.50" → "65.5", "0.001000" → "0.001", "1.2345678901234567890" → "1.2345678901234567")
    format!("{}", f)
}

/// Constructs the deterministic string representation of the provided JSON value.
///
/// The same JSON document can be represented in multiple ways depending on
/// property ordering and string encoding. This canonical JSON format lists
/// property names in ascending order by their utf8-encoded byte arrays and
/// uses the [NFKD normalized] unicode representation of all strings
/// (both property names and string values).
///
/// The function will return error if a provided JSON object has properties
/// with the same name in different unicode normalizations.
/// Note that creating `Value` arguments, `serde_json` accepts objects
/// having properties with exactly the same name and keeps only the last value,
/// ignoring all previous ones.
///
/// [NFKD normalized]: https://en.wikipedia.org/wiki/Unicode_equivalence#Normal_forms
pub fn canonical_json(data: &serde_json::Value) -> Result<String> {
    walk_json(data, &[], &mut |_, _| WalkAction::Keep)
}

/// Replace JSON (sub)tree(s) with their multibase-encoded [Merkle-root hash] strings.
///
/// Argument `keep_paths` can be created using function [`split_alternatives`] as needed.
///
/// [`split_alternatives`]: ../json_path/fn.split_alternatives.html
/// [Merkle-root hash]: https://en.wikipedia.org/wiki/Merkle_tree
pub fn mask_json_subtree<'b>(
    data: &serde_json::Value, keep_paths: impl AsRef<[&'b str]>,
) -> Result<serde_json::Value> {
    let parsed: Vec<Vec<&'b str>> =
        keep_paths.as_ref().iter().map(|p| split_path(p)).collect::<Result<_>>()?;

    let mut decider = |path: &[String], _val: &serde_json::Value| -> WalkAction {
        if parsed.is_empty() {
            return WalkAction::Hash;
        }
        for kp in &parsed {
            if path_starts_with(path, kp) || path_starts_with(kp, path) {
                return WalkAction::Keep;
            }
        }
        WalkAction::Hash
    };

    let result_str = walk_json(data, &[], &mut decider)?;
    serde_json::from_str(&result_str).map_err(Into::into)
}

/// Convenience function to transform a JSON value into a (partially) masked JSON value.
/// Only subtrees matching the provided JSON path pattern will be kept,
/// all other subtrees will be masked.
///
/// Nearly equivalent to `mask_json_subtree(&json_value, split_alternatives(keep_paths_str))`,
/// but always returns a string, not a `serde_json::Value`.
pub fn selective_digest_json(
    json_value: &serde_json::Value, keep_paths_str: &str,
) -> Result<String> {
    let keep_paths_vec = json_path::split_alternatives(keep_paths_str);
    let digest_json = match &json_value {
        serde_json::Value::Object(_obj) => mask_json_subtree(json_value, keep_paths_vec),
        serde_json::Value::Array(_arr) => mask_json_subtree(json_value, keep_paths_vec),
        serde_json::Value::String(_s) => Ok(json_value.to_owned()),
        _ => bail!("Json digest is currently implemented only for composite types"),
    }?;
    match digest_json {
        serde_json::Value::String(digest) => Ok(digest),
        // TODO probably a serde_json::to_string() would be enough and faster
        serde_json::Value::Object(_) => canonical_json(&digest_json),
        _ => bail!("Implementation error: digest should always return a string or object"),
    }
}

/// Convenience function calling [`selective_digest_json`] with arbitrary serializable types.
///
/// [`selective_digest_json`]: ./fn.selective_digest_json.html
pub fn selective_digest_data<T: serde::Serialize>(
    data: &T, keep_paths_str: &str,
) -> Result<String> {
    let json_value = serde_json::to_value(data)?;
    selective_digest_json(&json_value, keep_paths_str)
}

/// Convenience function calling [`selective_digest_json`] with a JSON string.
///
/// [`selective_digest_json`]: ./fn.selective_digest_json.html
pub fn selective_digest_json_str(json_str: &str, keep_paths_str: &str) -> Result<String> {
    ensure!(
        json_str == normalize_unicode(json_str),
        "Json string to be digested must be normalized with Unicode NFKD"
    );

    let json_value: serde_json::Value = serde_json::from_str(json_str)?;
    selective_digest_json(&json_value, keep_paths_str)
}

const KEEP_NOTHING: &str = "";

/// Convenience function for serializable types to mask the whole JSON tree into a digest, keep nothing.
pub fn digest_data<T: serde::Serialize>(data: &T) -> Result<String> {
    selective_digest_data(data, KEEP_NOTHING)
}

/// Convenience function for JSON strings to mask the whole JSON tree into a digest, keep nothing.
pub fn digest_json_str(json_str: &str) -> Result<String> {
    selective_digest_json_str(json_str, KEEP_NOTHING)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TestData {
        b: u32,
        a: u32,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct CompositeTestData<T> {
        z: Option<T>,
        y: Option<T>,
    }

    #[test]
    fn reject_non_nfkd() -> Result<()> {
        let key_nfc = String::from_utf8(Vec::from_hex("c3a16c6f6d").unwrap()).unwrap();
        let key_nfkd = String::from_utf8(Vec::from_hex("61cc816c6f6d").unwrap()).unwrap();
        assert_eq!(key_nfc, "álom");
        assert_eq!(key_nfkd, "álom");

        let str_nfc = format!("{{\"{key_nfc}\": 1}}");
        let str_nfkd = format!("{{\"{key_nfkd}\": 1}}");
        assert_eq!(digest_json_str(&str_nfkd)?, "cjuRab8yOeLzxmFY_fEMC79cW5z9XyihRhaGnTSvMabrA8");
        assert!(digest_json_str(&str_nfc).is_err());

        let json_value_nfc: serde_json::Value = serde_json::from_str(&str_nfc)?;
        let json_value_nfkd: serde_json::Value = serde_json::from_str(&str_nfkd)?;
        assert_eq!(
            selective_digest_json(&json_value_nfkd, "")?,
            "cjuRab8yOeLzxmFY_fEMC79cW5z9XyihRhaGnTSvMabrA8"
        );
        assert!(selective_digest_json(&json_value_nfc, "").is_err());
        Ok(())
    }

    #[test]
    fn digest_string_is_idempotent() {
        let content_id = &r#""cjuzC-XxgzNMwYXtw8aMIAeS2Xjlw1hlSNKTvVtUwPuyYo""#;
        let digest_id = digest_data(content_id).unwrap();
        assert_eq!(content_id, &digest_id);
    }

    #[test]
    fn test_json_digest() -> Result<()> {
        let test_obj = TestData { b: 1, a: 2 };
        {
            let digested = digest_data(&test_obj)?;
            assert_eq!(digested, "cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU");
        }
        {
            let digested = digest_data(&[&test_obj, &test_obj])?;
            assert_eq!(digested, "cjuGkDpb1HL7F8xFKDFVj3felfKZzjrJy92-108uuPixNw");
        }
        {
            let digested =
                digest_data(&(&test_obj, "cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU"))?;
            assert_eq!(digested, "cjuGkDpb1HL7F8xFKDFVj3felfKZzjrJy92-108uuPixNw");
        }
        {
            let digested = digest_data(&[
                "cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU",
                "cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU",
            ])?;
            assert_eq!(digested, "cjuGkDpb1HL7F8xFKDFVj3felfKZzjrJy92-108uuPixNw");
        }
        {
            let x = &test_obj;
            let comp = CompositeTestData { z: Some(x.clone()), y: Some(x.clone()) };
            let digested = digest_data(&comp)?;
            assert_eq!(digested, "cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ");
        }
        {
            let comp = CompositeTestData {
                z: Some("cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU".to_owned()),
                y: Some("cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU".to_owned()),
            };
            let digested = digest_data(&comp)?;
            assert_eq!(digested, "cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ");
        }
        Ok(())
    }

    #[test]
    fn test_selective_digesting() -> Result<()> {
        let test_obj = TestData { b: 1, a: 2 };
        let x = &test_obj;
        let composite = CompositeTestData { z: Some(x.clone()), y: Some(x.clone()) };
        let double_complex =
            CompositeTestData { z: Some(composite.clone()), y: Some(composite.clone()) };
        let triple_complex =
            CompositeTestData { z: Some(double_complex.clone()), y: Some(double_complex.clone()) };
        {
            let fully_digested = selective_digest_data(&composite, "")?;
            assert_eq!(fully_digested, "cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ");
        }
        {
            let keep_y = selective_digest_data(&composite, ".y")?;
            assert_eq!(
                keep_y,
                r#"{"y":{"a":2,"b":1},"z":"cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU"}"#
            );
            let val: serde_json::Value = serde_json::from_str(&keep_y)?;
            assert_eq!(digest_data(&val)?, "cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ");
        }
        {
            let keep_z = selective_digest_data(&composite, ".z")?;
            assert_eq!(
                keep_z,
                r#"{"y":"cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU","z":{"a":2,"b":1}}"#
            );
            let val: serde_json::Value = serde_json::from_str(&keep_z)?;
            assert_eq!(digest_data(&val)?, "cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ");
        }
        {
            let digest = digest_data(&double_complex)?;
            assert_eq!(digest, "cjuQLebyl_BJipFLibhWiStDBqK5J4JZq15ehUqybfTTKA");
        }
        {
            let keep_yz = selective_digest_data(&double_complex, ".y.z")?;
            assert_eq!(
                keep_yz,
                r#"{"y":{"y":"cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU","z":{"a":2,"b":1}},"z":"cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ"}"#
            );
            let val: serde_json::Value = serde_json::from_str(&keep_yz)?;
            assert_eq!(digest_data(&val)?, "cjuQLebyl_BJipFLibhWiStDBqK5J4JZq15ehUqybfTTKA");
        }
        {
            let digest = digest_data(&triple_complex)?;
            assert_eq!(digest, "cjuik140L3w7LCi6z1eHt7Qgwr2X65-iy8HA6zqrlUdmVk");
        }
        {
            let keep_yz = selective_digest_data(&triple_complex, ".y.y , .z.z")?;
            assert_eq!(
                keep_yz,
                r#"{"y":{"y":{"y":{"a":2,"b":1},"z":{"a":2,"b":1}},"z":"cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ"},"z":{"y":"cjubdcpA0FfHhD8yEpDzZ8vS5sm7yxkrX_wAJgmke2bWRQ","z":{"y":{"a":2,"b":1},"z":{"a":2,"b":1}}}}"#
            );
            let val: serde_json::Value = serde_json::from_str(&keep_yz)?;
            assert_eq!(digest_data(&val)?, "cjuik140L3w7LCi6z1eHt7Qgwr2X65-iy8HA6zqrlUdmVk");
        }
        Ok(())
    }

    /// Load test vectors from the canonical test vector JSON file.
    fn load_test_vectors() -> serde_json::Value {
        let data = include_str!("../canonical-json-digest.json");
        serde_json::from_str(data).expect("Failed to parse test vectors")
    }

    #[test]
    fn test_canonical_vectors() -> Result<()> {
        let vectors = load_test_vectors();
        let test_cases = vectors["vectors"].as_array().expect("vectors should be an array");

        let mut failures = Vec::new();
        for case in test_cases {
            let id = case["id"].as_str().unwrap_or("<unknown>");
            let input = &case["input"];
            let expected_digest =
                case["expected"]["digestHash"].as_str().expect("digestHash should be a string");

            // If canonical form is specified, check it
            if let Some(expected_canonical) = case["expected"]["canonical"].as_str() {
                let canonical = canonical_json(input)?;
                if canonical != expected_canonical {
                    failures.push(format!(
                        "[{}] canonical_json mismatch:\n  expected: {}\n  got:      {}",
                        id, expected_canonical, canonical
                    ));
                }
            }

            // Check digest
            let digest = digest_data(input)?;
            if digest != expected_digest {
                failures.push(format!(
                    "[{}] digest mismatch:\n  expected: {}\n  got:      {}",
                    id, expected_digest, digest
                ));
            }
        }

        if !failures.is_empty() {
            bail!("Vector test failures:\n{}", failures.join("\n\n"));
        }
        Ok(())
    }

    #[test]
    fn test_canonical_selective_vectors() -> Result<()> {
        let vectors = load_test_vectors();
        let test_cases =
            vectors["selectiveVectors"].as_array().expect("selectiveVectors should be an array");

        let mut failures = Vec::new();
        for case in test_cases {
            let id = case["id"].as_str().unwrap_or("<unknown>");
            let input = &case["input"];
            let keep_paths = case["keepPaths"].as_str().expect("keepPaths should be a string");
            let expected_selective = case["expected"]["selectiveDigest"]
                .as_str()
                .expect("selectiveDigest should be a string");
            let expected_redigest =
                case["expected"]["redigestHash"].as_str().expect("redigestHash should be a string");

            let selective = selective_digest_data(input, keep_paths)?;
            if selective != expected_selective {
                failures.push(format!(
                    "[{}] selectiveDigest mismatch:\n  expected: {}\n  got:      {}",
                    id, expected_selective, selective
                ));
            }

            let redigest = digest_data(&serde_json::from_str::<serde_json::Value>(&selective)?)?;
            if redigest != expected_redigest {
                failures.push(format!(
                    "[{}] redigest mismatch:\n  expected: {}\n  got:      {}",
                    id, expected_redigest, redigest
                ));
            }
        }

        if !failures.is_empty() {
            bail!("Selective vector test failures:\n{}", failures.join("\n\n"));
        }
        Ok(())
    }
}
