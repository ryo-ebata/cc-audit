pub mod json;
pub mod sarif;
pub mod terminal;

use crate::rules::ScanResult;

pub trait Reporter {
    fn report(&self, result: &ScanResult) -> String;
}
