//! Abstract interpretation lattice for nil tracking.

/// Nilability state in the abstract interpretation lattice.
///
/// Ordering: Bottom (None) < NonNil < MaybeNil
///                           Nil   < MaybeNil
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nilability {
    /// Guaranteed not nil (alloc, make, after != nil check)
    NonNil,
    /// May or may not be nil (function return, phi merge)
    MaybeNil,
    /// Guaranteed nil (nil literal, after == nil check)
    Nil,
}

impl Nilability {
    /// Join two nilability states (least upper bound)
    pub fn join(self, other: Nilability) -> Nilability {
        match (self, other) {
            (a, b) if a == b => a,
            _ => Nilability::MaybeNil,
        }
    }

    /// True if the value might be nil at runtime
    pub fn is_possibly_nil(self) -> bool {
        matches!(self, Nilability::MaybeNil | Nilability::Nil)
    }
}

/// Join with Option<Nilability> where None = bottom (unreached)
pub fn join_optional(a: Option<Nilability>, b: Option<Nilability>) -> Option<Nilability> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(a.join(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_same() {
        assert_eq!(
            Nilability::NonNil.join(Nilability::NonNil),
            Nilability::NonNil
        );
        assert_eq!(Nilability::Nil.join(Nilability::Nil), Nilability::Nil);
        assert_eq!(
            Nilability::MaybeNil.join(Nilability::MaybeNil),
            Nilability::MaybeNil
        );
    }

    #[test]
    fn test_join_different() {
        assert_eq!(
            Nilability::NonNil.join(Nilability::Nil),
            Nilability::MaybeNil
        );
        assert_eq!(
            Nilability::Nil.join(Nilability::NonNil),
            Nilability::MaybeNil
        );
    }

    #[test]
    fn test_join_with_maybe() {
        assert_eq!(
            Nilability::NonNil.join(Nilability::MaybeNil),
            Nilability::MaybeNil
        );
        assert_eq!(
            Nilability::Nil.join(Nilability::MaybeNil),
            Nilability::MaybeNil
        );
    }

    #[test]
    fn test_is_possibly_nil() {
        assert!(!Nilability::NonNil.is_possibly_nil());
        assert!(Nilability::MaybeNil.is_possibly_nil());
        assert!(Nilability::Nil.is_possibly_nil());
    }

    #[test]
    fn test_option_nilability_as_bottom() {
        let bottom: Option<Nilability> = None;
        assert!(bottom.is_none());
        let result = join_optional(bottom, Some(Nilability::NonNil));
        assert_eq!(result, Some(Nilability::NonNil));
        let result = join_optional(Some(Nilability::Nil), bottom);
        assert_eq!(result, Some(Nilability::Nil));
        let result = join_optional(bottom, bottom);
        assert_eq!(result, None);
    }
}
