//! Go source code parsing via tree-sitter-go.
//!
//! Provides functions to parse Go source code into a tree-sitter CST,
//! and extract structured information from the parse tree.
//!
//! Used ONLY for LSP error-tolerant editing — primary parsing is done
//! by goguard-go-bridge (Go binary) via Fat Bridge.

use tree_sitter::{Language, Node, Parser, Tree};

/// Errors that can occur during parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("failed to initialize parser: {0}")]
    InitError(String),
    #[error("failed to parse source code")]
    ParseFailed,
    #[error("invalid UTF-8 in source")]
    InvalidUtf8,
}

/// A parsed Go source file.
#[derive(Debug)]
pub struct ParsedFile {
    /// The tree-sitter parse tree.
    pub tree: Tree,
    /// The original source code.
    pub source: String,
    /// File path (if known).
    pub file_path: Option<String>,
}

impl ParsedFile {
    /// Returns the root node of the parse tree.
    pub fn root_node(&self) -> Node<'_> {
        self.tree.root_node()
    }

    /// Returns true if the parse tree contains any errors.
    pub fn has_errors(&self) -> bool {
        self.tree.root_node().has_error()
    }

    /// Get the source text for a given node.
    pub fn node_text(&self, node: &Node<'_>) -> &str {
        node.utf8_text(self.source.as_bytes()).unwrap_or("")
    }
}

/// Initialize a tree-sitter parser for Go.
fn create_parser() -> Result<Parser, ParseError> {
    let mut parser = Parser::new();
    let language: Language = tree_sitter_go::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|e| ParseError::InitError(e.to_string()))?;
    Ok(parser)
}

/// Parse Go source code into a tree-sitter parse tree.
pub fn parse_go(source: &str) -> Result<ParsedFile, ParseError> {
    let mut parser = create_parser()?;
    let tree = parser.parse(source, None).ok_or(ParseError::ParseFailed)?;

    Ok(ParsedFile {
        tree,
        source: source.to_string(),
        file_path: None,
    })
}

/// Parse Go source code with a known file path.
pub fn parse_go_file(source: &str, file_path: &str) -> Result<ParsedFile, ParseError> {
    let mut parsed = parse_go(source)?;
    parsed.file_path = Some(file_path.to_string());
    Ok(parsed)
}

/// Represents a Go source position.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourcePosition {
    pub line: usize,   // 1-based
    pub column: usize, // 0-based
    pub byte_offset: usize,
}

/// Represents a span in Go source code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceSpan {
    pub start: SourcePosition,
    pub end: SourcePosition,
}

impl SourceSpan {
    /// Create a SourceSpan from a tree-sitter node.
    pub fn from_node(node: &Node<'_>) -> Self {
        let start = node.start_position();
        let end = node.end_position();
        Self {
            start: SourcePosition {
                line: start.row + 1,
                column: start.column,
                byte_offset: node.start_byte(),
            },
            end: SourcePosition {
                line: end.row + 1,
                column: end.column,
                byte_offset: node.end_byte(),
            },
        }
    }
}

/// Extracted Go function declaration.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoFunction {
    pub name: String,
    pub receiver: Option<String>,
    pub params: Vec<GoParam>,
    pub returns: Vec<GoParam>,
    pub span: SourceSpan,
    pub body_span: Option<SourceSpan>,
    pub is_exported: bool,
}

/// A function parameter or return value.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoParam {
    pub name: Option<String>,
    pub type_text: String,
}

/// Extracted Go struct declaration.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoStruct {
    pub name: String,
    pub fields: Vec<GoField>,
    pub span: SourceSpan,
    pub is_exported: bool,
}

/// A struct field.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoField {
    pub name: String,
    pub type_text: String,
    pub tag: Option<String>,
    pub is_embedded: bool,
}

/// Extracted Go interface declaration.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoInterface {
    pub name: String,
    pub methods: Vec<GoInterfaceMethod>,
    pub span: SourceSpan,
    pub is_exported: bool,
}

/// An interface method signature.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoInterfaceMethod {
    pub name: String,
    pub params: Vec<GoParam>,
    pub returns: Vec<GoParam>,
}

/// Extract all function declarations from a parsed file.
pub fn extract_functions(parsed: &ParsedFile) -> Vec<GoFunction> {
    let mut functions = Vec::new();
    let root = parsed.root_node();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                if let Some(func) = extract_function_decl(&child, parsed) {
                    functions.push(func);
                }
            }
            "method_declaration" => {
                if let Some(func) = extract_method_decl(&child, parsed) {
                    functions.push(func);
                }
            }
            _ => {}
        }
    }

    functions
}

fn extract_function_decl(node: &Node<'_>, parsed: &ParsedFile) -> Option<GoFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = parsed.node_text(&name_node).to_string();

    let params = node
        .child_by_field_name("parameters")
        .map(|n| extract_params(&n, parsed))
        .unwrap_or_default();

    let returns = node
        .child_by_field_name("result")
        .map(|n| extract_return_types(&n, parsed))
        .unwrap_or_default();

    let body_span = node
        .child_by_field_name("body")
        .map(|n| SourceSpan::from_node(&n));

    Some(GoFunction {
        is_exported: name.starts_with(|c: char| c.is_uppercase()),
        name,
        receiver: None,
        params,
        returns,
        span: SourceSpan::from_node(node),
        body_span,
    })
}

fn extract_method_decl(node: &Node<'_>, parsed: &ParsedFile) -> Option<GoFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = parsed.node_text(&name_node).to_string();

    let params = node
        .child_by_field_name("parameters")
        .map(|n| extract_params(&n, parsed))
        .unwrap_or_default();

    let returns = node
        .child_by_field_name("result")
        .map(|n| extract_return_types(&n, parsed))
        .unwrap_or_default();

    let body_span = node
        .child_by_field_name("body")
        .map(|n| SourceSpan::from_node(&n));

    let receiver = node
        .child_by_field_name("receiver")
        .map(|n| parsed.node_text(&n).to_string());

    Some(GoFunction {
        is_exported: name.starts_with(|c: char| c.is_uppercase()),
        name,
        receiver,
        params,
        returns,
        span: SourceSpan::from_node(node),
        body_span,
    })
}

fn extract_params(params_node: &Node<'_>, parsed: &ParsedFile) -> Vec<GoParam> {
    let mut params = Vec::new();
    let mut cursor = params_node.walk();

    for child in params_node.children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            let type_node = child.child_by_field_name("type");
            let type_text = type_node
                .map(|n| parsed.node_text(&n).to_string())
                .unwrap_or_default();

            // Collect named parameters via the "name" field.
            // parameter_declaration can have multiple "name" children (e.g. `x, y int`).
            let mut name_cursor = child.walk();
            let mut names: Vec<String> = Vec::new();
            for name_child in child.children_by_field_name("name", &mut name_cursor) {
                names.push(parsed.node_text(&name_child).to_string());
            }

            if names.is_empty() {
                // Unnamed parameter
                params.push(GoParam {
                    name: None,
                    type_text,
                });
            } else {
                for n in names {
                    params.push(GoParam {
                        name: Some(n),
                        type_text: type_text.clone(),
                    });
                }
            }
        }
    }

    params
}

fn extract_return_types(result_node: &Node<'_>, parsed: &ParsedFile) -> Vec<GoParam> {
    let mut returns = Vec::new();

    match result_node.kind() {
        "parameter_list" => {
            // Multiple return values in parentheses
            returns = extract_params(result_node, parsed);
        }
        _ => {
            // Single return type (no parentheses)
            returns.push(GoParam {
                name: None,
                type_text: parsed.node_text(result_node).to_string(),
            });
        }
    }

    returns
}

/// Extract all struct type declarations from a parsed file.
pub fn extract_structs(parsed: &ParsedFile) -> Vec<GoStruct> {
    let mut structs = Vec::new();
    let root = parsed.root_node();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        if child.kind() == "type_declaration" {
            let mut spec_cursor = child.walk();
            for spec in child.children(&mut spec_cursor) {
                if spec.kind() == "type_spec" {
                    if let Some(s) = extract_struct_spec(&spec, parsed) {
                        structs.push(s);
                    }
                }
            }
        }
    }

    structs
}

fn extract_struct_spec(spec: &Node<'_>, parsed: &ParsedFile) -> Option<GoStruct> {
    let name_node = spec.child_by_field_name("name")?;
    let name = parsed.node_text(&name_node).to_string();

    let type_node = spec.child_by_field_name("type")?;
    if type_node.kind() != "struct_type" {
        return None;
    }

    let mut fields = Vec::new();

    // struct_type has a child field_declaration_list (no field name, just a child)
    let mut struct_cursor = type_node.walk();
    let field_list = type_node
        .children(&mut struct_cursor)
        .find(|n| n.kind() == "field_declaration_list")?;

    let mut cursor = field_list.walk();

    for child in field_list.children(&mut cursor) {
        if child.kind() == "field_declaration" {
            let type_child = child.child_by_field_name("type");
            let type_text = type_child
                .map(|n| parsed.node_text(&n).to_string())
                .unwrap_or_default();

            let tag = child
                .child_by_field_name("tag")
                .map(|n| parsed.node_text(&n).to_string());

            // Collect field names via the "name" field
            let mut name_cursor = child.walk();
            let mut names: Vec<String> = Vec::new();
            for name_child in child.children_by_field_name("name", &mut name_cursor) {
                names.push(parsed.node_text(&name_child).to_string());
            }

            if names.is_empty() {
                // Embedded field
                fields.push(GoField {
                    name: type_text.clone(),
                    type_text,
                    tag,
                    is_embedded: true,
                });
            } else {
                for n in names {
                    fields.push(GoField {
                        name: n,
                        type_text: type_text.clone(),
                        tag: tag.clone(),
                        is_embedded: false,
                    });
                }
            }
        }
    }

    Some(GoStruct {
        is_exported: name.starts_with(|c: char| c.is_uppercase()),
        name,
        fields,
        span: SourceSpan::from_node(spec),
    })
}

/// Extract all interface declarations from a parsed file.
pub fn extract_interfaces(parsed: &ParsedFile) -> Vec<GoInterface> {
    let mut interfaces = Vec::new();
    let root = parsed.root_node();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        if child.kind() == "type_declaration" {
            let mut spec_cursor = child.walk();
            for spec in child.children(&mut spec_cursor) {
                if spec.kind() == "type_spec" {
                    if let Some(iface) = extract_interface_spec(&spec, parsed) {
                        interfaces.push(iface);
                    }
                }
            }
        }
    }

    interfaces
}

fn extract_interface_spec(spec: &Node<'_>, parsed: &ParsedFile) -> Option<GoInterface> {
    let name_node = spec.child_by_field_name("name")?;
    let name = parsed.node_text(&name_node).to_string();

    let type_node = spec.child_by_field_name("type")?;
    if type_node.kind() != "interface_type" {
        return None;
    }

    let mut methods = Vec::new();
    let mut cursor = type_node.walk();
    for child in type_node.children(&mut cursor) {
        // In tree-sitter-go 0.25, interface methods are `method_elem` nodes
        // with `name`, `parameters`, and `result` fields directly.
        if child.kind() == "method_elem" {
            if let Some(method) = extract_interface_method_elem(&child, parsed) {
                methods.push(method);
            }
        }
    }

    Some(GoInterface {
        is_exported: name.starts_with(|c: char| c.is_uppercase()),
        name,
        methods,
        span: SourceSpan::from_node(spec),
    })
}

fn extract_interface_method_elem(
    method_node: &Node<'_>,
    parsed: &ParsedFile,
) -> Option<GoInterfaceMethod> {
    let name_node = method_node.child_by_field_name("name")?;
    let name = parsed.node_text(&name_node).to_string();

    let params = method_node
        .child_by_field_name("parameters")
        .map(|n| extract_params(&n, parsed))
        .unwrap_or_default();

    let returns = method_node
        .child_by_field_name("result")
        .map(|n| extract_return_types(&n, parsed))
        .unwrap_or_default();

    Some(GoInterfaceMethod {
        name,
        params,
        returns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_function() {
        let source = r#"
package main

func GetUser(id int) (*User, error) {
    return nil, nil
}
"#;
        let parsed = parse_go(source).unwrap();
        assert!(!parsed.has_errors());
        assert_eq!(parsed.root_node().kind(), "source_file");

        let functions = extract_functions(&parsed);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "GetUser");
        assert!(functions[0].is_exported);
        assert_eq!(functions[0].params.len(), 1);
        assert_eq!(functions[0].params[0].name.as_deref(), Some("id"));
        assert_eq!(functions[0].params[0].type_text, "int");
        assert_eq!(functions[0].returns.len(), 2);
    }

    #[test]
    fn test_parse_method() {
        let source = r#"
package main

type DB struct{}

func (db *DB) FindByID(id int) (*User, error) {
    return nil, nil
}
"#;
        let parsed = parse_go(source).unwrap();
        let functions = extract_functions(&parsed);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "FindByID");
        assert!(functions[0].receiver.is_some());
    }

    #[test]
    fn test_parse_struct() {
        let source = r#"
package main

type User struct {
    Name  string
    Email string `json:"email"`
    Age   int
}
"#;
        let parsed = parse_go(source).unwrap();
        let structs = extract_structs(&parsed);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "User");
        assert!(structs[0].is_exported);
        assert_eq!(structs[0].fields.len(), 3);
        assert_eq!(structs[0].fields[0].name, "Name");
        assert_eq!(structs[0].fields[1].name, "Email");
        assert!(structs[0].fields[1].tag.is_some());
    }

    #[test]
    fn test_parse_interface() {
        let source = r#"
package main

type Handler interface {
    Handle(event string) error
    Close() error
}
"#;
        let parsed = parse_go(source).unwrap();
        let interfaces = extract_interfaces(&parsed);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "Handler");
        assert_eq!(interfaces[0].methods.len(), 2);
        assert_eq!(interfaces[0].methods[0].name, "Handle");
        assert_eq!(interfaces[0].methods[1].name, "Close");
    }

    #[test]
    fn test_parse_error_recovery() {
        let source = "package main\nfunc broken(";
        let parsed = parse_go(source).unwrap();
        assert!(parsed.has_errors());
        // Should still have a root node
        assert_eq!(parsed.root_node().kind(), "source_file");
    }

    #[test]
    fn test_parse_multiple_functions() {
        let source = r#"
package main

func foo() {}
func bar(x int, y string) (bool, error) { return false, nil }
func baz() string { return "" }
"#;
        let parsed = parse_go(source).unwrap();
        let functions = extract_functions(&parsed);
        assert_eq!(functions.len(), 3);
        assert_eq!(functions[0].name, "foo");
        assert_eq!(functions[1].name, "bar");
        assert_eq!(functions[1].params.len(), 2);
        assert_eq!(functions[1].returns.len(), 2);
        assert_eq!(functions[2].name, "baz");
        assert_eq!(functions[2].returns.len(), 1);
    }

    #[test]
    fn test_parse_goroutine() {
        let source = r#"
package main

func main() {
    go func() {
        println("hello")
    }()
}
"#;
        let parsed = parse_go(source).unwrap();
        assert!(!parsed.has_errors());
    }

    #[test]
    fn test_parse_channel_operations() {
        let source = r#"
package main

func main() {
    ch := make(chan int)
    go func() {
        ch <- 42
    }()
    val := <-ch
    _ = val
}
"#;
        let parsed = parse_go(source).unwrap();
        assert!(!parsed.has_errors());
    }

    #[test]
    fn test_parse_type_switch() {
        let source = r#"
package main

func process(val any) {
    switch v := val.(type) {
    case string:
        println(v)
    case int:
        println(v)
    default:
        println("unknown")
    }
}
"#;
        let parsed = parse_go(source).unwrap();
        assert!(!parsed.has_errors());
    }

    #[test]
    fn test_parse_defer() {
        let source = r#"
package main

import "os"

func readFile() error {
    f, err := os.Open("test.txt")
    if err != nil {
        return err
    }
    defer f.Close()
    return nil
}
"#;
        let parsed = parse_go(source).unwrap();
        assert!(!parsed.has_errors());
    }

    #[test]
    fn test_parse_select() {
        let source = r#"
package main

func main() {
    ch1 := make(chan int)
    ch2 := make(chan string)
    select {
    case v := <-ch1:
        println(v)
    case s := <-ch2:
        println(s)
    default:
        println("no data")
    }
}
"#;
        let parsed = parse_go(source).unwrap();
        assert!(!parsed.has_errors());
    }

    #[test]
    fn test_source_span() {
        let source = r#"package main

func Hello() {
}
"#;
        let parsed = parse_go(source).unwrap();
        let functions = extract_functions(&parsed);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].span.start.line, 3);
        assert_eq!(functions[0].span.end.line, 4);
    }

    #[test]
    fn test_unexported_function() {
        let source = r#"
package main

func helper() {}
"#;
        let parsed = parse_go(source).unwrap();
        let functions = extract_functions(&parsed);
        assert_eq!(functions.len(), 1);
        assert!(!functions[0].is_exported);
    }
}
