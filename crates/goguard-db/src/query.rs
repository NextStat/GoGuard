//! GoGuard QL — a small query language for exploring analysis results.
//!
//! # Syntax examples
//!
//! ```text
//! diagnostics where severity == "critical"
//! diagnostics where file == "handler.go" and rule starts_with "NIL"
//! functions order_by diagnostic_count desc limit 10
//! packages where has_rule("NIL*") and has_rule("ERR*")
//! callers of "mypackage.ProcessRequest"
//! taint_paths from "http.Request" to "sql.DB.Query"
//! ```

use winnow::ascii::{digit1, space0, space1};
use winnow::combinator::{alt, delimited, opt};
use winnow::error::ContextError;
use winnow::token::take_while;
use winnow::{ModalResult, Parser};

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// The entity (table) that a query targets.
#[derive(Debug, Clone, PartialEq)]
pub enum Entity {
    Diagnostics,
    Functions,
    Packages,
    Callers { target: String },
    TaintPaths { from: String, to: String },
}

/// A filter predicate.
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Eq(String, String),
    Ne(String, String),
    StartsWith(String, String),
    Contains(String, String),
    HasRule(String),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
}

/// Sort direction.
#[derive(Debug, Clone, PartialEq)]
pub enum SortOrder {
    Asc,
    Desc,
}

/// A parsed GoGuard QL query.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub entity: Entity,
    pub filter: Option<Filter>,
    pub order_by: Option<(String, SortOrder)>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse a GoGuard QL query string into a [`Query`] AST.
pub fn parse_query(input: &str) -> Result<Query, String> {
    let mut input = input.trim();
    query_parser
        .parse_next(&mut input)
        .map_err(|e| format!("parse error: {e}"))
}

// ---------------------------------------------------------------------------
// Helper: try to match a keyword, returning bool.
// Restores input on failure.
// ---------------------------------------------------------------------------

/// Try to consume `keyword` from `input`. Returns `true` if matched.
/// On failure, the input is restored to its previous position.
/// Only matches if followed by whitespace, `"`, `(`, `)`, or end of input
/// (i.e., a word boundary).
fn try_keyword(input: &mut &str, keyword: &str) -> bool {
    let s = *input;
    if !s.starts_with(keyword) {
        return false;
    }
    let rest = &s[keyword.len()..];
    // Check word boundary.
    let next = rest.chars().next();
    if next.is_some()
        && next != Some(' ')
        && next != Some('\t')
        && next != Some('"')
        && next != Some('(')
        && next != Some(')')
    {
        return false;
    }
    *input = rest;
    true
}

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

fn query_parser(input: &mut &str) -> ModalResult<Query> {
    let entity = parse_entity(input)?;
    let _ = space0(input)?;

    let filter = parse_optional_where(input)?;
    let _ = space0(input)?;

    let order_by = parse_optional_order_by(input)?;
    let _ = space0(input)?;

    let limit = parse_optional_limit(input)?;
    let _ = space0(input)?;

    let offset = parse_optional_offset(input)?;
    let _ = space0(input)?;

    Ok(Query {
        entity,
        filter,
        order_by,
        limit,
        offset,
    })
}

// ---------------------------------------------------------------------------
// Entity parsers
// ---------------------------------------------------------------------------

fn parse_entity(input: &mut &str) -> ModalResult<Entity> {
    alt((parse_taint_paths, parse_callers, parse_simple_entity)).parse_next(input)
}

fn parse_simple_entity(input: &mut &str) -> ModalResult<Entity> {
    let name: &str = alt(("diagnostics", "functions", "packages")).parse_next(input)?;
    match name {
        "diagnostics" => Ok(Entity::Diagnostics),
        "functions" => Ok(Entity::Functions),
        "packages" => Ok(Entity::Packages),
        _ => unreachable!(),
    }
}

fn parse_callers(input: &mut &str) -> ModalResult<Entity> {
    let _: &str = "callers".parse_next(input)?;
    let _ = space1(input)?;
    let _: &str = "of".parse_next(input)?;
    let _ = space1(input)?;
    let target = parse_quoted_string(input)?;
    Ok(Entity::Callers { target })
}

fn parse_taint_paths(input: &mut &str) -> ModalResult<Entity> {
    let _: &str = "taint_paths".parse_next(input)?;
    let _ = space1(input)?;
    let _: &str = "from".parse_next(input)?;
    let _ = space1(input)?;
    let from = parse_quoted_string(input)?;
    let _ = space1(input)?;
    let _: &str = "to".parse_next(input)?;
    let _ = space1(input)?;
    let to = parse_quoted_string(input)?;
    Ok(Entity::TaintPaths { from, to })
}

// ---------------------------------------------------------------------------
// WHERE clause
// ---------------------------------------------------------------------------

fn parse_optional_where(input: &mut &str) -> ModalResult<Option<Filter>> {
    if !try_keyword(input, "where") {
        return Ok(None);
    }
    let _ = space1(input)?;
    let filter = parse_filter_expr(input)?;
    Ok(Some(filter))
}

/// Parse a filter expression with `and` / `or` connectors (left-associative).
fn parse_filter_expr(input: &mut &str) -> ModalResult<Filter> {
    let lhs = parse_filter_atom(input)?;
    parse_filter_chain(input, lhs)
}

fn parse_filter_chain(input: &mut &str, lhs: Filter) -> ModalResult<Filter> {
    let _ = space0(input)?;

    // Try "and"
    if try_keyword(input, "and") {
        let _ = space1(input)?;
        let rhs = parse_filter_atom(input)?;
        let combined = Filter::And(Box::new(lhs), Box::new(rhs));
        return parse_filter_chain(input, combined);
    }

    // Try "or"
    if try_keyword(input, "or") {
        let _ = space1(input)?;
        let rhs = parse_filter_atom(input)?;
        let combined = Filter::Or(Box::new(lhs), Box::new(rhs));
        return parse_filter_chain(input, combined);
    }

    Ok(lhs)
}

fn parse_filter_atom(input: &mut &str) -> ModalResult<Filter> {
    alt((parse_has_rule, parse_comparison)).parse_next(input)
}

/// `has_rule("PATTERN")`
fn parse_has_rule(input: &mut &str) -> ModalResult<Filter> {
    let _: &str = "has_rule".parse_next(input)?;
    let _ = space0(input)?;
    let pattern = delimited('(', parse_quoted_string, ')').parse_next(input)?;
    Ok(Filter::HasRule(pattern))
}

/// `field op value` — where op is `==`, `!=`, `starts_with`, `contains`.
fn parse_comparison(input: &mut &str) -> ModalResult<Filter> {
    let field = parse_identifier(input)?;
    let _ = space1(input)?;

    // Try operator keywords (must check before == / !=)
    if try_keyword(input, "starts_with") {
        let _ = space1(input)?;
        let value = parse_quoted_string(input)?;
        return Ok(Filter::StartsWith(field, value));
    }

    if try_keyword(input, "contains") {
        let _ = space1(input)?;
        let value = parse_quoted_string(input)?;
        return Ok(Filter::Contains(field, value));
    }

    // == or !=
    let op: &str = alt(("==", "!=")).parse_next(input)?;
    let _ = space0(input)?;
    let value = parse_quoted_string(input)?;

    match op {
        "==" => Ok(Filter::Eq(field, value)),
        "!=" => Ok(Filter::Ne(field, value)),
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// ORDER BY
// ---------------------------------------------------------------------------

fn parse_optional_order_by(input: &mut &str) -> ModalResult<Option<(String, SortOrder)>> {
    if !try_keyword(input, "order_by") {
        return Ok(None);
    }
    let _ = space1(input)?;
    let field = parse_identifier(input)?;
    let _ = space0(input)?;

    let order: Option<&str> = opt(alt(("desc", "asc"))).parse_next(input)?;
    let sort_order = match order {
        Some("desc") => SortOrder::Desc,
        _ => SortOrder::Asc,
    };

    Ok(Some((field, sort_order)))
}

// ---------------------------------------------------------------------------
// LIMIT / OFFSET
// ---------------------------------------------------------------------------

fn parse_optional_limit(input: &mut &str) -> ModalResult<Option<usize>> {
    parse_optional_usize_keyword(input, "limit")
}

fn parse_optional_offset(input: &mut &str) -> ModalResult<Option<usize>> {
    parse_optional_usize_keyword(input, "offset")
}

fn parse_optional_usize_keyword(
    input: &mut &str,
    keyword: &str,
) -> ModalResult<Option<usize>, ContextError> {
    if !try_keyword(input, keyword) {
        return Ok(None);
    }
    let _ = space1(input)?;
    let digits: &str = digit1(input)?;
    let n: usize = digits.parse().expect("digit1 always produces valid digits");
    Ok(Some(n))
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Parse a double-quoted string, returning the inner content.
fn parse_quoted_string(input: &mut &str) -> ModalResult<String> {
    let inner: &str = delimited('"', take_while(0.., |c: char| c != '"'), '"').parse_next(input)?;
    Ok(inner.to_string())
}

/// Parse an identifier: `[a-zA-Z_][a-zA-Z0-9_]*`.
fn parse_identifier(input: &mut &str) -> ModalResult<String> {
    let s: &str = take_while(1.., |c: char| c.is_alphanumeric() || c == '_').parse_next(input)?;
    Ok(s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_diagnostics() {
        let q = parse_query("diagnostics").unwrap();
        assert_eq!(q.entity, Entity::Diagnostics);
        assert!(q.filter.is_none());
    }

    #[test]
    fn test_parse_where_eq() {
        let q = parse_query("diagnostics where severity == \"critical\"").unwrap();
        assert_eq!(q.entity, Entity::Diagnostics);
        assert_eq!(
            q.filter,
            Some(Filter::Eq("severity".into(), "critical".into()))
        );
    }

    #[test]
    fn test_parse_where_starts_with() {
        let q = parse_query("diagnostics where rule starts_with \"NIL\"").unwrap();
        assert_eq!(
            q.filter,
            Some(Filter::StartsWith("rule".into(), "NIL".into()))
        );
    }

    #[test]
    fn test_parse_where_and() {
        let q =
            parse_query("diagnostics where file == \"a.go\" and severity == \"error\"").unwrap();
        match q.filter {
            Some(Filter::And(_, _)) => {}
            other => panic!("Expected And filter, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_order_by() {
        let q = parse_query("functions order_by diagnostic_count desc").unwrap();
        assert_eq!(q.entity, Entity::Functions);
        assert_eq!(
            q.order_by,
            Some(("diagnostic_count".into(), SortOrder::Desc))
        );
    }

    #[test]
    fn test_parse_limit_offset() {
        let q = parse_query("diagnostics limit 10 offset 5").unwrap();
        assert_eq!(q.limit, Some(10));
        assert_eq!(q.offset, Some(5));
    }

    #[test]
    fn test_parse_callers_of() {
        let q = parse_query("callers of \"pkg.Func\"").unwrap();
        assert_eq!(
            q.entity,
            Entity::Callers {
                target: "pkg.Func".into()
            }
        );
    }

    #[test]
    fn test_parse_taint_paths() {
        let q = parse_query("taint_paths from \"http.Request\" to \"sql.DB.Query\"").unwrap();
        assert_eq!(
            q.entity,
            Entity::TaintPaths {
                from: "http.Request".into(),
                to: "sql.DB.Query".into(),
            }
        );
    }
}
