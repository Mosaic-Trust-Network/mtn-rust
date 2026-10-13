//! Pinned ABI qualification only; callers must authenticate the runtime profile.
use frame_metadata::{
    META_RESERVED, RuntimeMetadata, RuntimeMetadataPrefixed,
    v14::{RuntimeMetadataV14, StorageEntryModifier, StorageEntryType, StorageHasher},
};
use mosaic_did_types::ContentId;
use parity_scale_codec::{Decode, Encode, MemTrackingInput};
use polkadot_sdk::sp_crypto_hashing::blake2_256;
use scale_info::{PortableRegistry, Registry, TypeDef, meta_type};
use wasm_bindgen::prelude::*;

const INVALID: &str = "invalid before-proof metadata input";
const MAX_SCALE: usize = 512 * 1024;
const MAX_MEMORY: usize = 8 * 1024 * 1024;

/// Check an independently pinned metadata hash and the exact V14 BeforeProofs ABI.
/// This does not prove metadata's association with a header, runtime code or network.
#[wasm_bindgen]
pub fn qualify_before_proof_metadata_v1(
    expected_hash: &[u8], scale: &[u8],
) -> Result<bool, String> {
    if expected_hash.len() != 32 || scale.len() < 5 || scale.len() > MAX_SCALE {
        return Err(INVALID.into());
    }
    if blake2_256(scale) != expected_hash {
        return Ok(false);
    }
    if scale[..4] != META_RESERVED.to_le_bytes() || scale[4] != 14 {
        return Err(INVALID.into());
    }
    let mut input = scale;
    let prefixed =
        RuntimeMetadataPrefixed::decode(&mut MemTrackingInput::new(&mut input, MAX_MEMORY))
            .map_err(|_| INVALID)?;
    if !input.is_empty() || prefixed.encode() != scale {
        return Err(INVALID.into());
    }
    let RuntimeMetadata::V14(metadata) = prefixed.1 else {
        return Err(INVALID.into());
    };
    Ok(qualify_layout(&metadata))
}

fn qualify_layout(metadata: &RuntimeMetadataV14) -> bool {
    if metadata.types.types.iter().enumerate().any(|(index, ty)| ty.id as usize != index) {
        return false;
    }
    let mut pallets = metadata.pallets.iter().filter(|p| p.name == "Did");
    let Some(pallet) = pallets.next() else {
        return false;
    };
    if pallets.next().is_some() {
        return false;
    }
    let Some(storage) = &pallet.storage else {
        return false;
    };
    if storage.prefix != "Did" {
        return false;
    }
    let mut entries = storage.entries.iter().filter(|e| e.name == "BeforeProofs");
    let Some(entry) = entries.next() else {
        return false;
    };
    if entries.next().is_some() || entry.modifier != StorageEntryModifier::Optional {
        return false;
    }
    let StorageEntryType::Map { hashers, key, value } = &entry.ty else {
        return false;
    };
    if hashers.as_slice() != [StorageHasher::Blake2_128Concat] {
        return false;
    }
    let mut native = Registry::new();
    let native_id = native.register_type(&meta_type::<ContentId>()).id;
    let native = native.into();
    if !same_layout(&native, native_id, &metadata.types, key.id, 0) {
        return false;
    }
    let Some(ty) = metadata.types.resolve(value.id) else {
        return false;
    };
    let TypeDef::Composite(record) = &ty.type_def else {
        return false;
    };
    record.fields.len() == 2
        && record.fields.iter().zip(["block_height", "extrinsic_index"]).all(|(field, name)| {
            field.name.as_deref() == Some(name)
                && matches!(
                    metadata.types.resolve(field.ty.id).map(|t| &t.type_def),
                    Some(TypeDef::Primitive(scale_info::TypeDefPrimitive::U32))
                )
        })
}

// ContentId's native graph is finite; the depth cap also rejects hostile cycles.
// Registry positions and Rust type paths do not define SCALE wire semantics.
fn same_layout(a: &PortableRegistry, x: u32, b: &PortableRegistry, y: u32, depth: u8) -> bool {
    if depth > 32 {
        return false;
    }
    let (Some(x), Some(y)) = (a.resolve(x), b.resolve(y)) else {
        return false;
    };
    let compare = |x, y| same_layout(a, x, b, y, depth + 1);
    let fields = |x: &[scale_info::Field<scale_info::form::PortableForm>],
                  y: &[scale_info::Field<scale_info::form::PortableForm>]| {
        x.len() == y.len()
            && x.iter().zip(y).all(|(x, y)| x.name == y.name && compare(x.ty.id, y.ty.id))
    };
    match (&x.type_def, &y.type_def) {
        (TypeDef::Primitive(x), TypeDef::Primitive(y)) => x == y,
        (TypeDef::Composite(x), TypeDef::Composite(y)) => fields(&x.fields, &y.fields),
        (TypeDef::Variant(x), TypeDef::Variant(y)) => {
            x.variants.len() == y.variants.len()
                && x.variants.iter().all(|x| {
                    y.variants
                        .iter()
                        .find(|y| x.index == y.index)
                        .is_some_and(|y| x.name == y.name && fields(&x.fields, &y.fields))
                })
        }
        (TypeDef::Sequence(x), TypeDef::Sequence(y)) => compare(x.type_param.id, y.type_param.id),
        (TypeDef::Array(x), TypeDef::Array(y)) => {
            x.len == y.len && compare(x.type_param.id, y.type_param.id)
        }
        (TypeDef::Tuple(x), TypeDef::Tuple(y)) => {
            x.fields.len() == y.fields.len()
                && x.fields.iter().zip(&y.fields).all(|(x, y)| compare(x.id, y.id))
        }
        (TypeDef::Compact(x), TypeDef::Compact(y)) => compare(x.type_param.id, y.type_param.id),
        (TypeDef::BitSequence(x), TypeDef::BitSequence(y)) => {
            compare(x.bit_store_type.id, y.bit_store_type.id)
                && compare(x.bit_order_type.id, y.bit_order_type.id)
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod test;
