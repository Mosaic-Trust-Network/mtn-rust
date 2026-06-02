use super::*;

// TODO compare these with mopheus_proto::data::diddoc::is_in_opt_range and friends. Also, Rust has a Range trait.
pub fn is_height_in_range_exc_until(
    height: BlockHeight, from_height_inc: Option<BlockHeight>,
    until_height_exc: Option<BlockHeight>,
) -> bool {
    if let Some(from) = from_height_inc
        && height < from
    {
        return false;
    }

    if let Some(until) = until_height_exc
        && height >= until
    {
        return false;
    }

    true
}

pub fn is_height_in_range_inc_until(
    height: BlockHeight, from_height_inc: Option<BlockHeight>,
    until_height_inc: Option<BlockHeight>,
) -> bool {
    if let Some(from) = from_height_inc
        && height < from
    {
        return false;
    }

    if let Some(until) = until_height_inc
        && height > until
    {
        return false;
    }

    true
}
