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

pub struct SampleBuilder {
    pub(super) features_mask: u32,
}

impl SampleBuilder {
    pub fn build<I>(&self, features: I, class: f32) -> Sample
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut features_map = HashMap::with_capacity_and_hasher(128, BuildNoHashHasher::default());

        for feature in features {
            let feature = feature.as_ref();
            let hash = xxh3_64_with_seed(feature, 0) as u32;
            let hash_sign = xxh3_64_with_seed(feature, 1);

            *features_map.entry(hash & self.features_mask).or_default() +=
                if hash_sign & 1 == 0 { 1.0 } else { -1.0 };
        }

        Sample {
            features: Features(features_map),
            class,
        }
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
