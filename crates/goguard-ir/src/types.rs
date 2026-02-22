//! Type system helpers for working with Go types from bridge data.

use crate::ir::{Package, TypeKind, TypeRef};
use std::collections::HashMap;

/// Type lookup table for a package
pub struct TypeMap {
    types: HashMap<u32, TypeRef>,
}

impl TypeMap {
    pub fn from_package(pkg: &Package) -> Self {
        let types = pkg.types.iter().map(|t| (t.id, t.clone())).collect();
        Self { types }
    }

    pub fn get(&self, id: u32) -> Option<&TypeRef> {
        self.types.get(&id)
    }

    pub fn is_nilable(&self, id: u32) -> bool {
        self.types.get(&id).map(|t| t.is_nilable).unwrap_or(false)
    }

    pub fn is_pointer(&self, id: u32) -> bool {
        self.types
            .get(&id)
            .map(|t| t.kind == TypeKind::Pointer)
            .unwrap_or(false)
    }

    pub fn is_interface(&self, id: u32) -> bool {
        self.types
            .get(&id)
            .map(|t| t.kind == TypeKind::Interface)
            .unwrap_or(false)
    }

    pub fn is_error_type(&self, id: u32) -> bool {
        self.types
            .get(&id)
            .map(|t| t.is_error || t.name == "error" || t.name.ends_with(".error"))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_type_map() -> TypeMap {
        let pkg = Package {
            import_path: "test".into(),
            name: "test".into(),
            files: vec![],
            types: vec![
                TypeRef {
                    id: 1,
                    kind: TypeKind::Basic,
                    name: "int".into(),
                    underlying: 0,
                    elem: 0,
                    key: 0,
                    is_nilable: false,
                    is_error: false,
                },
                TypeRef {
                    id: 2,
                    kind: TypeKind::Pointer,
                    name: "*User".into(),
                    underlying: 0,
                    elem: 3,
                    key: 0,
                    is_nilable: true,
                    is_error: false,
                },
                TypeRef {
                    id: 3,
                    kind: TypeKind::Struct,
                    name: "User".into(),
                    underlying: 0,
                    elem: 0,
                    key: 0,
                    is_nilable: false,
                    is_error: false,
                },
                TypeRef {
                    id: 4,
                    kind: TypeKind::Interface,
                    name: "error".into(),
                    underlying: 0,
                    elem: 0,
                    key: 0,
                    is_nilable: true,
                    is_error: true,
                },
                TypeRef {
                    id: 5,
                    kind: TypeKind::Map,
                    name: "map[string]int".into(),
                    underlying: 0,
                    elem: 1,
                    key: 0,
                    is_nilable: true,
                    is_error: false,
                },
            ],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };
        TypeMap::from_package(&pkg)
    }

    #[test]
    fn test_nilability() {
        let tm = make_type_map();
        assert!(!tm.is_nilable(1)); // int
        assert!(tm.is_nilable(2)); // *User
        assert!(!tm.is_nilable(3)); // User struct
        assert!(tm.is_nilable(4)); // error interface
        assert!(tm.is_nilable(5)); // map
    }

    #[test]
    fn test_type_checks() {
        let tm = make_type_map();
        assert!(tm.is_pointer(2));
        assert!(!tm.is_pointer(1));
        assert!(tm.is_interface(4));
        assert!(tm.is_error_type(4));
    }
}
