use super::*;

#[test]
fn wasm_codec_native_vectors_and_rejections() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("vectors/native.json")).unwrap();
    let hash: Vec<u8> = (0..32).collect();
    let did = derive_did(&hash).unwrap();
    assert_eq!(did, vectors["did"].as_str().unwrap());
    assert_eq!(serde_json::json!(did_scale(&did).unwrap()), vectors["didScale"]);
    for foreign in vectors["foreignDids"].as_array().unwrap() {
        assert!(parse_did(foreign["did"].as_str().unwrap()).is_err());
    }
    for (kind, display, scale) in [
        ("blake3-flat", "flatDisplay", "flatScale"),
        ("sha3-json", "sha3Display", "sha3Scale"),
        ("blake3-json", "blake3Display", "blake3Scale"),
    ] {
        let id = content_id_from_hash(&hash, kind).unwrap();
        assert_eq!(id, vectors[display].as_str().unwrap());
        assert_eq!(serde_json::json!(content_id_scale(&id).unwrap()), vectors[scale]);
    }
    for item in vectors["digests"].as_array().unwrap() {
        for algo in ["sha3", "blake3"] {
            assert_eq!(
                digest_json(item["jsonText"].as_str().unwrap(), algo).unwrap(),
                item[algo]["digest"].as_str().unwrap()
            );
        }
    }
    assert!(content_id_from_hash(&hash[..31], "sha3-json").is_err());
    assert!(content_id_from_hash(&hash, "unknown").is_err());
    assert!(digest_json("{", "blake3").is_err());
    assert!(digest_json("{}", "unknown").is_err());
    assert!(right_scale("owner").is_err());
    assert!(purpose_scale("issue").is_err());
}

#[test]
fn wasm_codec_bridge_roots_and_native_container_policy() {
    for algorithm in ["sha3", "blake3"] {
        assert_ne!(
            digest_json(r#"{"n":9007199254740992}"#, algorithm).unwrap(),
            digest_json(r#"{"n":9007199254740993}"#, algorithm).unwrap()
        );
        assert!(digest_json(r#"{"é":1}"#, algorithm).is_err());
        assert!(digest_json("1", algorithm).is_err());
        assert!(digest_json(r#""1""#, algorithm).is_err());
        assert_ne!(
            digest_json("[1,2]", algorithm).unwrap(),
            digest_json("[2,1]", algorithm).unwrap()
        );
        assert_eq!(
            digest_json(r#"{"b":2,"a":1}"#, algorithm).unwrap(),
            digest_json(r#"{"a":1,"b":2}"#, algorithm).unwrap()
        );
    }
}

mod envelope;
