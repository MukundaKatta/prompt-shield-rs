use crate::findings::Finding;

pub trait Rule: Send + Sync {
    fn name(&self) -> &str;
    fn scan(&self, text: &str) -> Vec<Finding>;
}
