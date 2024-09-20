pub mod bayes;
pub mod language;
pub mod tokenizers;

#[cfg(test)]
mod test {
    use std::fs;

    use crate::{
        bayes::{tokenize::BayesTokenizer, BayesClassifier, BayesModel},
        tokenizers::osb::{OsbToken, OsbTokenizer},
    };

    #[test]
    #[ignore]
    fn train() {
        let db =
            fs::read_to_string("/Users/me/code/mail-server/_ignore/spam_or_not_spam.csv").unwrap();
        let mut bayes = BayesModel::default();

        for line in db.lines() {
            let (text, is_spam) = line.rsplit_once(',').unwrap();
            let is_spam = is_spam == "1";

            bayes.train(OsbTokenizer::new(BayesTokenizer::new(text), 5), is_spam);
        }
        println!("Ham: {} Spam: {}", bayes.ham_learns, bayes.spam_learns,);
        fs::write(
            "/Users/me/code/mail-server/_ignore/spam_or_not_spam.bin",
            bincode::serialize(&bayes).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn classify() {
        let model: BayesModel = bincode::deserialize(
            &fs::read("/Users/me/code/mail-server/_ignore/spam_or_not_spam.bin").unwrap(),
        )
        .unwrap();
        let bayes = BayesClassifier::new();

        for text in [
            "i am attaching to this email a presentation to integrate the spreadsheet into our server",
            "buy this great product special offer sales",
            "i m using simple dns from jhsoft we support only a few web sites and i d like to swap secondary services with someone in a similar position",
            "viagra xenical vioxx zyban propecia we only offer the real viagra xenical ",
        ] {
            println!(
                "{:?} -> {}",
                text,
                bayes
                    .classify(OsbTokenizer::new(BayesTokenizer::new(text), 5).filter_map(|x| model.weights.get(&x.inner).map(|w| {
                        OsbToken {
                            idx: x.idx,
                            inner: *w,
                        }
                    })), model.ham_learns, model.spam_learns)
                    .unwrap()
            );
        }
    }
}
