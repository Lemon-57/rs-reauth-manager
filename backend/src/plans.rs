//! Team family classification preserves the exact upstream subscription value.
pub const BUSINESS_PROLITE: &str = "self_serve_business_prolite";

pub fn team(plan: &str) -> bool {
    matches!(plan.trim().to_ascii_lowercase().as_str(), "team" | "business" | BUSINESS_PROLITE)
}

pub fn same_family(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim()) || (team(left) && team(right))
}

pub fn fixed_scheduling(plan: &str) -> Option<(u64, u64)> {
    plan.trim().eq_ignore_ascii_case(BUSINESS_PROLITE).then_some((10, 10))
}
