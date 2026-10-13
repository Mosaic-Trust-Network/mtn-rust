use super::*;
use frame_metadata::{
    RuntimeMetadata, RuntimeMetadataPrefixed,
    v14::{RuntimeMetadataV14, StorageEntryModifier, StorageEntryType, StorageHasher},
};
use parity_scale_codec::{Decode, Encode};
use polkadot_sdk::sp_crypto_hashing::blake2_256;
use scale_info::{TypeDef, TypeDefPrimitive};
const SCALE: &[u8] = include_bytes!("../../../../tests/vectors/before-proof-runtime.scale");

fn metadata() -> RuntimeMetadataV14 {
    let RuntimeMetadata::V14(value) = RuntimeMetadataPrefixed::decode(&mut &SCALE[..]).unwrap().1
    else {
        panic!("V14 fixture required")
    };
    value
}
fn storage(
    m: &mut RuntimeMetadataV14,
) -> &mut frame_metadata::v14::PalletStorageMetadata<scale_info::form::PortableForm> {
    m.pallets.iter_mut().find(|p| p.name == "Did").unwrap().storage.as_mut().unwrap()
}
fn entry(
    m: &mut RuntimeMetadataV14,
) -> &mut frame_metadata::v14::StorageEntryMetadata<scale_info::form::PortableForm> {
    storage(m).entries.iter_mut().find(|e| e.name == "BeforeProofs").unwrap()
}
fn key_value(m: &mut RuntimeMetadataV14) -> (u32, u32) {
    let StorageEntryType::Map { key, value, .. } = &entry(m).ty else { panic!("map required") };
    (key.id, value.id)
}
fn qualified(m: RuntimeMetadataV14) -> Result<bool, String> {
    let bytes = RuntimeMetadataPrefixed::from(m).encode();
    // Re-pin mutations: semantic ABI checks must reject them even with a matching hash.
    qualify_before_proof_metadata_v1(&blake2_256(&bytes), &bytes)
}
#[test]
fn metadata_before_proof_accepts_exact_pinned_fixture_and_ignores_paths() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/vectors/before-proof-runtime.json"))
            .unwrap();
    let expected: Vec<u8> = serde_json::from_value(fixture["metadataHash"].clone()).unwrap();
    assert!(qualify_before_proof_metadata_v1(&expected, SCALE).unwrap());
    assert!(!qualify_before_proof_metadata_v1(&[0; 32], SCALE).unwrap());
    let mut m = metadata();
    for ty in &mut m.types.types {
        ty.ty.path.segments.clear();
    }
    assert!(qualified(m).unwrap());
}
#[test]
fn metadata_before_proof_rejects_storage_schema_drift_even_when_repinned() {
    for case in 0..9 {
        let mut m = metadata();
        match case {
            0 => storage(&mut m).prefix = "Wrong".into(),
            1 => entry(&mut m).modifier = StorageEntryModifier::Default,
            2 => {
                let StorageEntryType::Map { hashers, .. } = &mut entry(&mut m).ty else {
                    unreachable!()
                };
                *hashers = vec![StorageHasher::Identity];
            }
            3 => {
                let StorageEntryType::Map { hashers, .. } = &mut entry(&mut m).ty else {
                    unreachable!()
                };
                hashers.push(StorageHasher::Blake2_128Concat);
            }
            4 => {
                let e = entry(&mut m).clone();
                storage(&mut m).entries.push(e);
            }
            5 => {
                let p = m.pallets.iter().find(|p| p.name == "Did").unwrap().clone();
                m.pallets.push(p);
            }
            6 => {
                entry(&mut m).name = "Renamed".into();
            }
            7 => {
                let (_, v) = key_value(&mut m);
                entry(&mut m).ty = StorageEntryType::Plain(v.into());
            }
            _ => {
                m.pallets.retain(|p| p.name != "Did");
            }
        }
        assert!(!qualified(m).unwrap(), "case {case}");
    }
}
#[test]
fn metadata_before_proof_rejects_native_key_and_record_type_drift_even_when_repinned() {
    for case in 0..8 {
        let mut m = metadata();
        let (k, v) = key_value(&mut m);
        match case {
            0..=2 => {
                let TypeDef::Variant(ref mut variants) = m.types.types[k as usize].ty.type_def
                else {
                    panic!("native ContentId enum")
                };
                match case {
                    0 => variants.variants[0].index = 99,
                    1 => variants.variants[0].name = "Unknown".into(),
                    _ => {
                        variants.variants[0].fields.clear();
                    }
                }
            }
            3..=5 => {
                let TypeDef::Composite(ref mut record) = m.types.types[v as usize].ty.type_def
                else {
                    panic!("record")
                };
                match case {
                    3 => record.fields[0].name = Some("changed".into()),
                    4 => {
                        record.fields.pop();
                    }
                    _ => {
                        let field = record.fields[0].clone();
                        record.fields.push(field);
                    }
                }
            }
            6 => {
                let TypeDef::Composite(ref record) = m.types.types[v as usize].ty.type_def else {
                    unreachable!()
                };
                let id = record.fields[0].ty.id;
                m.types.types[id as usize].ty.type_def = TypeDef::Primitive(TypeDefPrimitive::U64);
            }
            _ => {
                let TypeDef::Composite(ref mut record) = m.types.types[v as usize].ty.type_def
                else {
                    unreachable!()
                };
                record.fields[0].ty = u32::MAX.into();
            }
        }
        assert!(!qualified(m).unwrap(), "case {case}");
    }
}
#[test]
fn metadata_before_proof_rejects_invalid_envelopes_and_bounded_inputs() {
    assert!(qualify_before_proof_metadata_v1(&[0; 31], SCALE).is_err());
    for bytes in [
        vec![],
        SCALE[..SCALE.len() - 1].to_vec(),
        [SCALE, &[0]].concat(),
        vec![0; 512 * 1024 + 1],
        vec![b'm', b'e', b't', b'a', 0x0e, 0xff, 0xff, 0xff, 0xff, 0x3f],
    ] {
        assert!(qualify_before_proof_metadata_v1(&blake2_256(&bytes), &bytes).is_err());
    }
    let mut magic = SCALE.to_vec();
    magic[0] ^= 1;
    assert!(qualify_before_proof_metadata_v1(&blake2_256(&magic), &magic).is_err());
    let mut m = metadata();
    m.types.types[0].id = 2;
    assert!(!qualified(m).unwrap());
    let mut version = SCALE.to_vec();
    version[4] = 0;
    assert!(qualify_before_proof_metadata_v1(&blake2_256(&version), &version).is_err());
}
