//! State machine for tracking resource ownership transitions.
//!
//! Resources in Go (files, network connections, database handles, etc.)
//! follow a lifecycle: Open -> Use -> Close. This module defines the
//! state machine and transition logic for tracking these lifecycles.

use goguard_ir::ir::Span;

/// The lifecycle state of a tracked resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    /// Resource has been opened (via os.Open, sql.Open, etc.).
    Open,
    /// Resource has been used after opening (any operation on it).
    Used,
    /// Resource has been closed (via .Close() call or defer .Close()).
    Closed,
}

/// A resource being tracked through a function's execution.
#[derive(Debug, Clone)]
pub struct TrackedResource {
    /// The SSA instruction ID that opened this resource.
    pub instr_id: u32,
    /// Current lifecycle state.
    pub state: ResourceState,
    /// The callee that opened the resource (e.g., "os.Open").
    pub opener_callee: String,
    /// Source location of the opening call.
    pub span: Option<Span>,
    /// Whether a `defer resource.Close()` exists for this resource.
    pub has_defer_close: bool,
    /// Source location of the close call, if any.
    pub close_span: Option<Span>,
}

impl TrackedResource {
    /// Create a new tracked resource in the Open state.
    pub fn new(instr_id: u32, opener_callee: String, span: Option<Span>) -> Self {
        Self {
            instr_id,
            state: ResourceState::Open,
            opener_callee,
            span,
            has_defer_close: false,
            close_span: None,
        }
    }

    /// Transition to Used state (only valid from Open).
    pub fn mark_used(&mut self) {
        if self.state == ResourceState::Open {
            self.state = ResourceState::Used;
        }
    }

    /// Transition to Closed state. Returns true if this is a valid transition
    /// (from Open or Used), false if it was already Closed (double close).
    pub fn mark_closed(&mut self, close_span: Option<Span>) -> bool {
        match self.state {
            ResourceState::Open | ResourceState::Used => {
                self.state = ResourceState::Closed;
                self.close_span = close_span;
                true
            }
            ResourceState::Closed => false, // double close
        }
    }

    /// Mark that a defer close exists for this resource.
    pub fn mark_defer_close(&mut self) {
        self.has_defer_close = true;
        // Defer close counts as closed for lifecycle purposes
        match self.state {
            ResourceState::Open | ResourceState::Used => {
                self.state = ResourceState::Closed;
            }
            ResourceState::Closed => {} // already closed
        }
    }

    /// Check if the resource is still open (not closed).
    pub fn is_open(&self) -> bool {
        matches!(self.state, ResourceState::Open | ResourceState::Used)
    }
}

/// Known functions that open resources requiring Close().
///
/// These are standard library functions that return closeable resources.
pub fn is_resource_opener(callee: &str) -> bool {
    matches!(
        callee,
        // os package
        "os.Open"
            | "os.OpenFile"
            | "os.Create"
            | "os.CreateTemp"
            // sql package
            | "sql.Open"
            | "(*sql.DB).Begin"
            | "(*sql.DB).Query"
            | "(*sql.DB).QueryRow"
            | "(*sql.DB).QueryContext"
            | "(*sql.DB).BeginTx"
            | "(*sql.Tx).Query"
            | "(*sql.Tx).QueryRow"
            | "(*sql.Stmt).Query"
            | "(*sql.Stmt).QueryRow"
            // net package
            | "net.Dial"
            | "net.DialTimeout"
            | "net.Listen"
            | "net.ListenPacket"
            | "(*net.Dialer).Dial"
            | "(*net.Dialer).DialContext"
            // http package
            | "http.Get"
            | "http.Post"
            | "http.Head"
            | "(*http.Client).Do"
            | "(*http.Client).Get"
            | "(*http.Client).Post"
            | "(*http.Client).Head"
            | "(*http.Transport).RoundTrip"
            // bufio package
            | "bufio.NewReader"
            | "bufio.NewWriter"
            | "bufio.NewScanner"
            | "bufio.NewReadWriter"
            // gzip, zlib, etc.
            | "gzip.NewReader"
            | "gzip.NewWriter"
            | "zlib.NewReader"
            | "zlib.NewWriter"
    )
}

/// Check if a callee is a close method.
pub fn is_close_call(callee: &str) -> bool {
    callee.ends_with(".Close") || callee.ends_with(".close") || callee == "close"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_opener_os() {
        assert!(is_resource_opener("os.Open"));
        assert!(is_resource_opener("os.OpenFile"));
        assert!(is_resource_opener("os.Create"));
        assert!(is_resource_opener("os.CreateTemp"));
    }

    #[test]
    fn test_resource_opener_sql() {
        assert!(is_resource_opener("sql.Open"));
        assert!(is_resource_opener("(*sql.DB).Begin"));
        assert!(is_resource_opener("(*sql.DB).Query"));
    }

    #[test]
    fn test_resource_opener_net() {
        assert!(is_resource_opener("net.Dial"));
        assert!(is_resource_opener("net.DialTimeout"));
        assert!(is_resource_opener("net.Listen"));
    }

    #[test]
    fn test_resource_opener_http() {
        assert!(is_resource_opener("http.Get"));
        assert!(is_resource_opener("http.Post"));
        assert!(is_resource_opener("(*http.Client).Do"));
    }

    #[test]
    fn test_resource_opener_bufio() {
        assert!(is_resource_opener("bufio.NewReader"));
        assert!(is_resource_opener("bufio.NewWriter"));
        assert!(is_resource_opener("bufio.NewScanner"));
    }

    #[test]
    fn test_not_resource_opener() {
        assert!(!is_resource_opener("fmt.Println"));
        assert!(!is_resource_opener("strings.NewReader"));
        assert!(!is_resource_opener("json.Marshal"));
        assert!(!is_resource_opener("os.ReadFile"));
    }

    #[test]
    fn test_is_close_call() {
        assert!(is_close_call("(*os.File).Close"));
        assert!(is_close_call("(*sql.DB).Close"));
        assert!(is_close_call("(*net.TCPConn).Close"));
        assert!(is_close_call("io.Closer.Close"));
        assert!(is_close_call("close"));
    }

    #[test]
    fn test_is_not_close_call() {
        assert!(!is_close_call("os.Open"));
        assert!(!is_close_call("fmt.Println"));
        assert!(!is_close_call("closeConnection")); // does not end with .Close
    }

    #[test]
    fn test_tracked_resource_lifecycle() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        assert_eq!(res.state, ResourceState::Open);
        assert!(res.is_open());

        res.mark_used();
        assert_eq!(res.state, ResourceState::Used);
        assert!(res.is_open());

        assert!(res.mark_closed(None));
        assert_eq!(res.state, ResourceState::Closed);
        assert!(!res.is_open());
    }

    #[test]
    fn test_tracked_resource_double_close() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        assert!(res.mark_closed(None));
        assert!(!res.mark_closed(None)); // double close returns false
    }

    #[test]
    fn test_tracked_resource_defer_close() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        res.mark_defer_close();
        assert!(res.has_defer_close);
        assert_eq!(res.state, ResourceState::Closed);
        assert!(!res.is_open());
    }

    #[test]
    fn test_tracked_resource_mark_used_only_from_open() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        res.mark_closed(None);
        // mark_used after Closed should not change state
        res.mark_used();
        assert_eq!(res.state, ResourceState::Closed);
    }

    #[test]
    fn test_tracked_resource_close_from_open() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        assert!(res.mark_closed(None));
        assert_eq!(res.state, ResourceState::Closed);
    }

    #[test]
    fn test_tracked_resource_close_from_used() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        res.mark_used();
        assert!(res.mark_closed(None));
        assert_eq!(res.state, ResourceState::Closed);
    }

    #[test]
    fn test_tracked_resource_defer_close_when_already_closed() {
        let mut res = TrackedResource::new(0, "os.Open".to_string(), None);
        res.mark_closed(None);
        res.mark_defer_close(); // should not panic
        assert!(res.has_defer_close);
        assert_eq!(res.state, ResourceState::Closed);
    }
}
