/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use nohash::BuildNoHashHasher;
use std::collections::HashMap;
use xxhash_rust::xxh3::xxh3_64_with_seed;

pub struct Sample {
    pub(super) features: Features,
    pub(super) class: f32,
}

pub struct Features(pub(super) HashMap<u32, f32, BuildNoHashHasher<u32>>);

pub struct FeatureBuilder {
    pub(super) features_mask: u32,
}

pub trait Feature {
    fn prefix(&self) -> u16;
    fn value(&self) -> &[u8];
    fn is_global_feature(&self) -> bool;
    fn is_local_feature(&self) -> bool;
}

impl FeatureBuilder {
    pub fn scale<I: Feature>(&self, features: &mut HashMap<I, f32>) {
        // Log frequency scaling
        for x in features.values_mut() {
            *x = x.ln_1p();
        }
    }

    pub fn build<I: Feature>(
        &self,
        features: &HashMap<I, f32>,
        account_id: Option<u32>,
    ) -> Features {
        // Do the "hash trick"
        let mut features_map =
            HashMap::with_capacity_and_hasher(features.len(), BuildNoHashHasher::default());
        let mut buf = Vec::with_capacity(2 + 4 + 63);
        for (feature, count) in features {
            buf.extend_from_slice(&feature.prefix().to_be_bytes());
            buf.extend_from_slice(feature.value());

            if feature.is_global_feature() {
                let big_hash = xxh3_64_with_seed(&buf, 0);
                let hash = big_hash as u32 & self.features_mask;
                let sign = if big_hash & (1 << 63) == 0 { 1.0 } else { -1.0 };

                *features_map.entry(hash).or_default() += sign * count;
            }

            if feature.is_local_feature()
                && let Some(account_id) = account_id
            {
                buf.extend_from_slice(&account_id.to_be_bytes());
                let big_hash = xxh3_64_with_seed(&buf, 0);
                let hash = big_hash as u32 & self.features_mask;
                let sign = if big_hash & (1 << 63) == 0 { 1.0 } else { -1.0 };

                *features_map.entry(hash).or_default() += sign * count;
            }
            buf.clear();
        }

        // L2 normalization
        let sum_of_squares = features_map
            .values()
            .map(|&x| x as f64 * x as f64)
            .sum::<f64>();
        if sum_of_squares > 0.0 {
            let norm = sum_of_squares.sqrt() as f32;
            for x in features_map.values_mut() {
                *x /= norm;
            }
        }

        Features(features_map)
    }
}

impl AsRef<Sample> for Sample {
    fn as_ref(&self) -> &Sample {
        self
    }
}

impl AsRef<Features> for Features {
    fn as_ref(&self) -> &Features {
        self
    }
}
