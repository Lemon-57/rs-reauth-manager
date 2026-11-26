//! Team family classification preserves the exact upstream subscription value.
pub const BUSINESS_PROLITE: &str = "self_serve_business_prolite";

pub fn fixed_team_schedule(plan: &str) -> Option<(u64, u64)> {
    plan.trim().eq_ignore_ascii_case("team").then_some((5, 1))
}

pub fn team(plan: &str) -> bool {
    matches!(
        plan.trim().to_ascii_lowercase().as_str(),
        "team" | "business" | BUSINESS_PROLITE
    )
}

pub fn same_family(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim()) || (team(left) && team(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_schedule_applies_to_the_exact_verified_team_plan() {
        for plan in ["team", " TEAM "] {
            assert_eq!(fixed_team_schedule(plan), Some((5, 1)));
        }
        for plan in [
            "business",
            BUSINESS_PROLITE,
            "self_serve_business_usage_based",
            "pro",
            "prolite",
            "free",
            "",
        ] {
            assert_eq!(fixed_team_schedule(plan), None);
        }
    }
}
