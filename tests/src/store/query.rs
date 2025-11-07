/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::store::deflate_test_resource;
use nlp::language::Language;
use std::{
    fmt::Display,
    io::Write,
    sync::{Arc, Mutex},
    time::Instant,
};
use store::{
    SearchStore, SerializeInfallible,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{
        EmailSearchField, IndexDocument, SearchComparator, SearchField, SearchFilter,
        SearchOperator, SearchQuery, SearchValue,
    },
    write::{Operation, SearchIndex, ValueClass},
};
use store::{Store, ValueKey, write::BatchBuilder};
use types::collection::Collection;
use utils::map::vec_map::VecMap;

pub const FIELDS: [&str; 20] = [
    "id",
    "accession_number",
    "artist",
    "artistRole",
    "artistId",
    "title",
    "dateText",
    "medium",
    "creditLine",
    "year",
    "acquisitionYear",
    "dimensions",
    "width",
    "height",
    "depth",
    "units",
    "inscription",
    "thumbnailCopyright",
    "thumbnailUrl",
    "url",
];

/*
 "title", // Subject
 "year".   // ReceivedAt
 "width",  // Size
 "height", // SentAt
 "artist" // Headers
 "artistRole" // Cc
 "medium",  // From
 "creditLine" // Body
 "acquisitionYear" // Bcc
 "accession_number" // To
*/

const FIELD_MAPPINGS: [EmailSearchField; 20] = [
    EmailSearchField::HasAttachment, // "id",
    EmailSearchField::To,            // "accession_number",
    EmailSearchField::Headers,       // "artist",
    EmailSearchField::Cc,            // "artistRole",
    EmailSearchField::HasAttachment, // "artistId",
    EmailSearchField::Subject,       // "title",
    EmailSearchField::HasAttachment, // "dateText",
    EmailSearchField::From,          // "medium",
    EmailSearchField::Body,          // "creditLine",
    EmailSearchField::ReceivedAt,    // "year",
    EmailSearchField::Bcc,           // "acquisitionYear",
    EmailSearchField::HasAttachment, // "dimensions",
    EmailSearchField::Size,          // "width",
    EmailSearchField::SentAt,        // "height",
    EmailSearchField::HasAttachment, // "depth",
    EmailSearchField::HasAttachment, // "units",
    EmailSearchField::HasAttachment, // "inscription",
    EmailSearchField::HasAttachment, // "thumbnailCopyright",
    EmailSearchField::HasAttachment, // "thumbnailUrl",
    EmailSearchField::HasAttachment, // "url",
];

#[allow(clippy::mutex_atomic)]
pub async fn test(store: SearchStore, do_insert: bool) {
    println!("Running Store query tests...");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    let now = Instant::now();
    let documents = Arc::new(Mutex::new(Vec::new()));

    if do_insert {
        pool.scope_fifo(|s| {
            for (document_id, record) in csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(&deflate_test_resource("artwork_data.csv.gz")[..])
                .records()
                .enumerate()
            {
                let record = record.unwrap();
                let documents = documents.clone();

                s.spawn_fifo(move |_| {
                    let mut document = IndexDocument::new(SearchIndex::Email)
                        .with_account_id(0)
                        .with_document_id(document_id as u32);
                    for (pos, field) in record.iter().enumerate() {
                        let field_id = pos as u8;
                        match FIELD_MAPPINGS[pos] {
                            EmailSearchField::From
                            | EmailSearchField::To
                            | EmailSearchField::Cc => {
                                document.index_text(
                                    FIELD_MAPPINGS[pos],
                                    &field.to_lowercase(),
                                    Language::None,
                                );
                            }
                            EmailSearchField::Subject
                            | EmailSearchField::Body
                            | EmailSearchField::Attachment => {
                                document.index_text(
                                    FIELD_MAPPINGS[pos],
                                    &field.to_lowercase(),
                                    Language::English,
                                );
                            }
                            EmailSearchField::Headers => {
                                document.insert_key_value(
                                    EmailSearchField::Headers,
                                    "artist",
                                    field.to_lowercase(),
                                );
                            }
                            EmailSearchField::ReceivedAt
                            | EmailSearchField::SentAt
                            | EmailSearchField::Size => {
                                document.index_unsigned(
                                    FIELD_MAPPINGS[pos],
                                    field.parse::<u64>().unwrap_or(0),
                                );
                            }
                            _ => {
                                continue;
                            }
                        };
                    }

                    documents.lock().unwrap().push(document);
                });
            }
        });

        println!(
            "Parsed {} entries in {} ms.",
            documents.lock().unwrap().len(),
            now.elapsed().as_millis()
        );

        let now = Instant::now();
        let batches = documents.lock().unwrap().drain(..).collect::<Vec<_>>();
        let mut chunk = Vec::new();
        let mut fts_chunk = Vec::new();

        print!("Inserting... ",);
        for document in batches {
            let chunk_instance = Instant::now();
            chunk.push({
                let db = db.clone();
                tokio::spawn(async move { db.write(batch.build_all()).await })
            });
            fts_chunk.push({
                let fts_store = fts_store.clone();
                tokio::spawn(async move { fts_store.index(fts_batch).await })
            });
            if chunk.len() == 1000 {
                for handle in chunk {
                    handle.await.unwrap().unwrap();
                }
                for handle in fts_chunk {
                    handle.await.unwrap().unwrap();
                }
                print!(" [{} ms]", chunk_instance.elapsed().as_millis());
                std::io::stdout().flush().unwrap();
                chunk = Vec::new();
                fts_chunk = Vec::new();
            }
        }

        if !chunk.is_empty() {
            for handle in chunk {
                handle.await.unwrap().unwrap();
            }
        }

        println!("\nInsert took {} ms.", now.elapsed().as_millis());
    }

    println!("Running filter tests...");
    let now = Instant::now();
    test_filter(db.clone(), fts_store).await;
    println!("Filtering took {} ms.", now.elapsed().as_millis());

    println!("Running sort tests...");
    let now = Instant::now();
    test_sort(db).await;
    println!("Sorting took {} ms.", now.elapsed().as_millis());
}

pub async fn test_filter(
    store: SearchStore,
    fields: &AHashMap<u32, &'static str>,
    mask: &RoaringBitmap,
) {
    let tests = [
        (
            vec![
                SearchFilter::has_english_text(EmailSearchField::Subject, "water"),
                SearchFilter::eq(EmailSearchField::ReceivedAt, 1979u32),
            ],
            vec!["p11293"],
        ),
        (
            vec![
                SearchFilter::has_keyword(EmailSearchField::From, "gelatin"),
                SearchFilter::gt(EmailSearchField::ReceivedAt, 2000u32),
                SearchFilter::lt(EmailSearchField::Size, 180u32),
                SearchFilter::gt(EmailSearchField::Size, 0u32),
            ],
            vec!["p79426", "p79427", "p79428", "p79429", "p79430"],
        ),
        (
            vec![SearchFilter::has_english_text(
                EmailSearchField::Subject,
                "'rustic bridge'",
            )],
            vec!["d05503"],
        ),
        (
            vec![
                SearchFilter::has_english_text(EmailSearchField::Subject, "'rustic'"),
                SearchFilter::has_english_text(EmailSearchField::Subject, "study"),
            ],
            vec!["d00399", "d05352"],
        ),
        (
            vec![
                SearchFilter::cond(
                    EmailSearchField::Headers,
                    SearchOperator::Contains,
                    SearchValue::KeyValues(VecMap::from_iter([(
                        "artist".to_string(),
                        "kunst mauro".to_string(),
                    )])),
                ),
                SearchFilter::has_keyword(EmailSearchField::Cc, "artist"),
                SearchFilter::Or,
                SearchFilter::eq(EmailSearchField::ReceivedAt, 1969u32),
                SearchFilter::eq(EmailSearchField::ReceivedAt, 1971u32),
                SearchFilter::End,
            ],
            vec!["p01764", "t05843"],
        ),
        (
            vec![
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "oil"),
                SearchFilter::End,
                SearchFilter::has_english_text(EmailSearchField::Body, "bequeath"),
                SearchFilter::Or,
                SearchFilter::And,
                SearchFilter::ge(EmailSearchField::ReceivedAt, 1900u32),
                SearchFilter::lt(EmailSearchField::ReceivedAt, 1910u32),
                SearchFilter::End,
                SearchFilter::And,
                SearchFilter::ge(EmailSearchField::ReceivedAt, 2000u32),
                SearchFilter::lt(EmailSearchField::ReceivedAt, 2010u32),
                SearchFilter::End,
                SearchFilter::End,
            ],
            vec![
                "n02478", "n02479", "n03568", "n03658", "n04327", "n04328", "n04721", "n04739",
                "n05095", "n05096", "n05145", "n05157", "n05158", "n05159", "n05298", "n05303",
                "n06070", "t01181", "t03571", "t05805", "t05806", "t12147", "t12154", "t12155",
            ],
        ),
        (
            vec![
                SearchFilter::And,
                SearchFilter::cond(
                    EmailSearchField::Headers,
                    SearchOperator::Contains,
                    SearchValue::KeyValues(VecMap::from_iter([(
                        "artist".to_string(),
                        "warhol".to_string(),
                    )])),
                ),
                SearchFilter::Not,
                SearchFilter::has_english_text(EmailSearchField::Subject, "'campbell'"),
                SearchFilter::End,
                SearchFilter::Not,
                SearchFilter::Or,
                SearchFilter::gt(EmailSearchField::ReceivedAt, 1980u32),
                SearchFilter::And,
                SearchFilter::gt(EmailSearchField::Size, 500u32),
                SearchFilter::gt(EmailSearchField::SentAt, 500u32),
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::eq(EmailSearchField::Bcc, "2008".to_string()),
                SearchFilter::End,
            ],
            vec!["ar00039", "t12600"],
        ),
        (
            vec![
                SearchFilter::has_english_text(EmailSearchField::Subject, "study"),
                SearchFilter::has_keyword(EmailSearchField::From, "paper"),
                SearchFilter::has_english_text(EmailSearchField::Body, "'purchased'"),
                SearchFilter::Not,
                SearchFilter::has_english_text(EmailSearchField::Subject, "'anatomical'"),
                SearchFilter::has_english_text(EmailSearchField::Subject, "'for'"),
                SearchFilter::End,
                SearchFilter::gt(EmailSearchField::ReceivedAt, 1900u32),
                SearchFilter::gt(EmailSearchField::Bcc, "2008".to_string()),
            ],
            vec![
                "p80042", "p80043", "p80044", "p80045", "p80203", "t11937", "t12172",
            ],
        ),
    ];

    for (filters, expected_results) in tests {
        //println!("Running test: {:?}", filter);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparator(SearchComparator::ascending(EmailSearchField::To))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in ids {
            results.push(*fields.get(&document_id).unwrap());
        }
        assert_eq!(results, expected_results);
    }
}

pub async fn test_sort(
    store: SearchStore,
    fields: &AHashMap<u32, &'static str>,
    mask: &RoaringBitmap,
) {
    let tests = [
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::gt(EmailSearchField::ReceivedAt, 0u32),
                SearchFilter::gt(EmailSearchField::Bcc, "0000".to_string()),
                SearchFilter::gt(EmailSearchField::Size, 0u32),
            ],
            vec![
                SearchComparator::descending(EmailSearchField::ReceivedAt),
                SearchComparator::ascending(EmailSearchField::Bcc),
                SearchComparator::ascending(EmailSearchField::Size),
                SearchComparator::descending(EmailSearchField::To),
            ],
            vec![
                "t13655", "t13811", "p13352", "p13351", "p13350", "p13349", "p13348", "p13347",
                "p13346", "p13345", "p13344", "p13342", "p13341", "p13340", "p13339", "p13338",
                "p13337", "p13336", "p13335", "p13334", "p13333", "p13332", "p13331", "p13330",
                "p13329", "p13328", "p13327", "p13326", "p13325", "p13324", "p13323", "t13786",
                "p13322", "p13321", "p13320", "p13319", "p13318", "p13317", "p13316", "p13315",
                "p13314", "t13588", "t13587", "t13586", "t13585", "t13584", "t13540", "t13444",
                "ar01154", "ar01153",
            ],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::gt(EmailSearchField::Size, 0u32),
                SearchFilter::gt(EmailSearchField::SentAt, 0u32),
            ],
            vec![
                SearchComparator::descending(EmailSearchField::Size),
                SearchComparator::ascending(EmailSearchField::SentAt),
            ],
            vec![
                "t03681", "t12601", "ar00166", "t12625", "t12915", "p04182", "t06483", "ar00703",
                "t07671", "ar00021", "t05557", "t07918", "p06298", "p05465", "p06640", "t12855",
                "t01355", "t12800", "t12557", "t02078",
            ],
        ),
        (
            vec![SearchFilter::eq(SearchField::AccountId, 0u32)],
            vec![
                SearchComparator::descending(EmailSearchField::From),
                SearchComparator::descending(EmailSearchField::Cc),
                SearchComparator::ascending(EmailSearchField::To),
            ],
            vec![
                "ar00627", "ar00052", "t00352", "t07275", "t12318", "t04931", "t13683", "t13686",
                "t13687", "t13688", "t13689", "t13690", "t13691", "t07766", "t07918", "t12993",
                "ar00044", "t13326", "t07614", "t12414",
            ],
        ),
    ];

    for (filters, comparators, expected_results) in tests {
        //println!("Running test: {:?}", sort);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in ids {
            results.push(*fields.get(&document_id).unwrap());
        }
        assert_eq!(results, expected_results);
    }
}
