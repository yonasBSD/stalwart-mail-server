/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::feature::{FeatureBuilder, Features, Sample};
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};

#[derive(Default)]
pub struct SGDClassifier {
    weights: Vec<f32>,
    intercept: f32,
    n_epochs: usize,
    alpha: f32,
    random_state: u64,
}

const MAX_DLOSS: f32 = 1e4;

impl SGDClassifier {
    pub fn new(n_features: usize, n_epochs: usize, alpha: f32, random_state: u64) -> Self {
        SGDClassifier {
            weights: vec![0.0; n_features],
            n_epochs,
            random_state,
            alpha,
            intercept: 0.0,
        }
    }

    pub fn fit(&mut self, samples: &mut [impl AsRef<Sample>]) {
        let mut rng = StdRng::seed_from_u64(self.random_state);
        let mut t = 1;
        let mut w_scale = 1.0;

        // Heuristic to initialize 'optimal' learning rate
        let typw = (1.0 / self.alpha.sqrt()).sqrt();
        let initial_eta0 = typw / 1.0_f32.max(gradient(1.0, -typw));
        let optimal_init = 1.0 / (initial_eta0 * self.alpha);

        for _ in 0..self.n_epochs {
            samples.shuffle(&mut rng);

            for sample in samples.iter() {
                // Prediction
                let sample = sample.as_ref();
                let mut dot: f32 = 0.0;
                for (idx, feature) in &sample.features.0 {
                    dot += self.weights[*idx as usize] * *feature;
                }
                let p = (dot * w_scale) + self.intercept;
                let eta = 1.0 / (self.alpha * (optimal_init + (t as f32) - 1.0));

                // Compute Loss & Gradient
                let dloss = gradient(sample.class, p).clamp(-MAX_DLOSS, MAX_DLOSS);

                // Lazy weight decay
                w_scale *= 1.0 - (eta * self.alpha);

                // Update weights
                let update = -eta * dloss;
                if update != 0.0 {
                    let scaled_update = update / w_scale;

                    for (idx, feature) in &sample.features.0 {
                        self.weights[*idx as usize] += scaled_update * *feature;
                    }

                    self.intercept += update;
                }

                // Rescale weights if w_scale is too small or too large
                if !(1e-6..=1e6).contains(&w_scale) {
                    for w in &mut self.weights {
                        *w *= w_scale;
                    }
                    w_scale = 1.0;
                }

                t += 1;
            }
        }

        if w_scale != 1.0 {
            for w in &mut self.weights {
                *w *= w_scale;
            }
        }
    }

    fn predict_proba_sample(&self, features: &Features) -> f32 {
        let mut z: f32 = 0.0;
        for (idx, feature) in &features.0 {
            z += self.weights[*idx as usize] * *feature;
        }
        z += self.intercept;

        sigmoid(z)
    }

    pub fn predict(&self, features: &Features) -> f32 {
        let proba = self.predict_proba_sample(features);
        if proba >= 0.5 { 1.0 } else { 0.0 }
    }

    pub fn predict_batch<I>(&self, test: I) -> Vec<f32>
    where
        I: IntoIterator,
        I::Item: AsRef<Features>,
    {
        test.into_iter()
            .map(|features| self.predict(features.as_ref()))
            .collect()
    }

    pub fn feature_builder(&self) -> FeatureBuilder {
        FeatureBuilder {
            features_mask: (self.weights.len() - 1) as u32,
        }
    }

    pub fn is_active(&self) -> bool {
        !self.weights.is_empty()
    }
}

#[inline(always)]
fn gradient(y: f32, p: f32) -> f32 {
    if p > -16.0 {
        let exp_tmp = (-p).exp();
        ((1.0 - y) - y * exp_tmp) / (1.0 + exp_tmp)
    } else {
        p.exp() - y
    }
}

#[inline(always)]
fn sigmoid(z: f32) -> f32 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let exp_z = z.exp();
        exp_z / (1.0 + exp_z)
    }
}

/*#[inline(always)]
fn loss(y: f32, p: f32) -> f32 {
    log1pexp(p) - y * p
}

#[inline(always)]
fn log1pexp(x: f32) -> f32 {
    if x <= -16.0 {
        x.exp()
    } else if x <= 16.0 {
        (1.0 + x.exp()).ln()
    } else {
        x
    }
}*/

#[cfg(test)]
pub mod tests {
    use crate::classifier::{
        feature::{Feature, Sample},
        sgd::SGDClassifier,
    };
    use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
    use std::{
        collections::HashMap,
        fs::File,
        io::{BufRead, BufReader},
        time::Instant,
    };

    fn accuracy_score(y_true: &[f32], y_pred: &[f32]) -> f32 {
        y_true
            .iter()
            .zip(y_pred.iter())
            .filter(|(true_val, pred_val)| **true_val == **pred_val)
            .count() as f32
            / y_true.len() as f32
    }

    fn precision_score(y_true: &[f32], y_pred: &[f32], positive_class: f32) -> f32 {
        let true_positives = y_true
            .iter()
            .zip(y_pred.iter())
            .filter(|(true_val, pred_val)| {
                **pred_val == positive_class && **true_val == positive_class
            })
            .count() as f32;

        let predicted_positives = y_pred
            .iter()
            .filter(|pred_val| **pred_val == positive_class)
            .count() as f32;

        if predicted_positives == 0.0 {
            0.0
        } else {
            true_positives / predicted_positives
        }
    }

    fn recall_score(y_true: &[f32], y_pred: &[f32], positive_class: f32) -> f32 {
        let true_positives = y_true
            .iter()
            .zip(y_pred.iter())
            .filter(|(true_val, pred_val)| {
                **pred_val == positive_class && **true_val == positive_class
            })
            .count() as f32;

        let actual_positives = y_true
            .iter()
            .filter(|true_val| **true_val == positive_class)
            .count() as f32;

        if actual_positives == 0.0 {
            0.0
        } else {
            true_positives / actual_positives
        }
    }

    fn f1_score(y_true: &[f32], y_pred: &[f32], positive_class: f32) -> f32 {
        let precision = precision_score(y_true, y_pred, positive_class);
        let recall = recall_score(y_true, y_pred, positive_class);

        if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * (precision * recall) / (precision + recall)
        }
    }

    fn train_test_split(data: &[Sample], test_size: f32) -> (Vec<&Sample>, Vec<&Sample>) {
        let mut class_0: Vec<&Sample> = Vec::new();
        let mut class_1: Vec<&Sample> = Vec::new();

        for sample in data {
            if sample.class == 0.0 {
                class_0.push(sample);
            } else {
                class_1.push(sample);
            }
        }

        let test_count_0 = (class_0.len() as f32 * test_size).round() as usize;
        let test_count_1 = (class_1.len() as f32 * test_size).round() as usize;

        let (test_0, train_0) = class_0.split_at(test_count_0);
        let (test_1, train_1) = class_1.split_at(test_count_1);

        let mut train = Vec::new();
        let mut test = Vec::new();

        train.extend_from_slice(train_0);
        train.extend_from_slice(train_1);
        test.extend_from_slice(test_0);
        test.extend_from_slice(test_1);

        (train, test)
    }

    impl Feature for String {
        fn prefix(&self) -> u16 {
            0
        }

        fn value(&self) -> &[u8] {
            self.as_bytes()
        }

        fn is_global_feature(&self) -> bool {
            true
        }

        fn is_local_feature(&self) -> bool {
            false
        }
    }

    #[test]
    fn sgd_classifier() {
        let reader = BufReader::new(
            File::open("/Users/me/code/playground/phishing_email.csv")
                .expect("Could not open file"),
        );
        let mut samples = Vec::with_capacity(1024);

        let mut model = SGDClassifier::new(1 << 20, 1000, 0.0001, 42);
        let builder = model.feature_builder();

        let time = Instant::now();

        for line in reader.lines().skip(1) {
            let line = line.unwrap();
            let (text, class) = line.trim().rsplit_once(',').unwrap();
            let text = text.trim_start_matches('"').trim_end_matches('"');

            let mut sample: HashMap<String, f32> = HashMap::new();
            for word in text.split_whitespace() {
                *sample.entry(word.to_string()).or_default() += 1.0;
            }
            builder.scale(&mut sample);
            samples.push(Sample {
                features: builder.build(&sample, None),
                class: class
                    .parse()
                    .unwrap_or_else(|_| panic!("Invalid class value: {line}")),
            });
        }

        println!("Loaded {} samples in {:?}", samples.len(), time.elapsed());

        samples.shuffle(&mut StdRng::seed_from_u64(42));

        let (mut train_samples, test_samples) = train_test_split(&samples, 0.2);

        println!(
            "Training samples: {}, Testing samples: {}",
            train_samples.len(),
            test_samples.len()
        );

        println!("Training SGD Classifier...");
        let time = Instant::now();
        model.fit(&mut train_samples);
        println!("SGD Classifier trained in {:?}", time.elapsed());

        let y_pred = model.predict_batch(test_samples.iter().map(|s| &s.features));
        let y_train: Vec<f32> = test_samples.iter().map(|s| s.class).collect();

        println!("Accuracy: {:.4}", accuracy_score(&y_train, &y_pred));
        println!("Precision: {:.4}", precision_score(&y_train, &y_pred, 1.0));
        println!("Recall: {:.4}", recall_score(&y_train, &y_pred, 1.0));
        println!("F1 Score: {:.4}", f1_score(&y_train, &y_pred, 1.0));
    }
}
