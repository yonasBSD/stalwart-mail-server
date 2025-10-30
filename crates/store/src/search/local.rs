/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::SearchFilter;

/*pub enum FilterGroup<T: FilterItem> {
    Fts(Vec<T>),
    Store(T),
}

fn split_local_remote(filter: Vec<SearchFilter>) -> Vec<FilterGroup<T>> {
    let mut filter = Vec::with_capacity(self.len());
    let mut iter = self.into_iter();
    let mut logical_op = None;

    while let Some(item) = iter.next() {
        if matches!(item.filter_type(), FilterType::Fts) {
            let mut store_item = None;
            let mut depth = 0;
            let mut fts = Vec::with_capacity(5);

            // Add the logical operator if there is one
            let in_logical_op = if let Some(op) = logical_op.take() {
                fts.push(op);
                true
            } else {
                false
            };
            fts.push(item);

            for item in iter.by_ref() {
                match item.filter_type() {
                    FilterType::And | FilterType::Or | FilterType::Not => {
                        depth += 1;
                        fts.push(item);
                    }
                    FilterType::End if depth > 0 => {
                        depth -= 1;
                        fts.push(item);
                    }
                    FilterType::Fts => {
                        fts.push(item);
                    }
                    _ => {
                        store_item = Some(item);
                        break;
                    }
                }
            }

            if in_logical_op {
                fts.push(T::from(FilterType::End));
            }

            if depth > 0 {
                let mut store = Vec::with_capacity(depth * 2);
                while depth > 0 {
                    let item = fts.pop().unwrap();
                    if matches!(
                        item.filter_type(),
                        FilterType::And | FilterType::Or | FilterType::Not
                    ) {
                        depth -= 1;
                    }
                    store.push(FilterGroup::Store(item));
                }

                filter.push(FilterGroup::Fts(fts));
                filter.extend(store);
            } else {
                filter.push(FilterGroup::Fts(fts));
            }

            if let Some(item) = store_item {
                filter.push(FilterGroup::Store(item));
            }
        } else {
            match item.filter_type() {
                FilterType::And | FilterType::Or => {
                    logical_op = Some(item.clone());
                }
                FilterType::Not => {
                    logical_op = Some(T::from(FilterType::And));
                }
                _ => {}
            }
            filter.push(FilterGroup::Store(item));
        }
    }

    filter
}
*/
