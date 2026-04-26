"""
Policy record dataclasses for the U-HAP DSL.

Five record types:
  RBACRecord   - role-based permission
  HierRecord   - role hierarchy (parent inherits child permissions)
  ABACRecord   - attribute-based conditional permission
  ACLRecord    - direct user permission
  DenyRecord   - unconditional deny (wildcard or specific user)
"""

from dataclasses import dataclass, field
from typing import Any, List, Dict, Set, Optional


@dataclass(frozen=True)
class RBACRecord:
    """Grants a role unconditional permission on a resource/action.

    π_rbac = ⟨role, resource, namespace, action⟩
    Creates edge: role --action--> resource
    """
    role: str
    resource: str
    namespace: str
    action: str


@dataclass(frozen=True)
class HierRecord:
    """Declares that parent_role inherits all permissions of child_role.

    π_hier = ⟨parent_role, child_role, namespace⟩
    Creates edge: parent_role → child_role  (no action label)
    Must be acyclic.
    """
    parent_role: str
    child_role: str
    namespace: str


@dataclass(frozen=True)
class ABACRecord:
    """Grants conditional permission based on a boolean predicate over context.

    π_abac = ⟨resource, namespace, action, predicate⟩
    predicate is a string that gets parsed into an AST.
    Creates edge: gate_node --action--> resource
    """
    resource: str
    namespace: str
    action: str
    predicate: str


@dataclass(frozen=True)
class ACLRecord:
    """Grants a specific subject direct permission on a resource/action.

    π_acl = ⟨subject, resource, namespace, action⟩
    Creates edge: subject --action--> resource
    The only record type that puts a specific user in the graph.
    """
    subject: str
    resource: str
    namespace: str
    action: str


@dataclass(frozen=True)
class DenyRecord:
    """Unconditional deny for a subject (or wildcard) on a resource/action.

    π_deny = ⟨subject_or_wildcard, resource, namespace, action⟩
    subject_or_wildcard: specific username or "*" (wildcard for all subjects)
    Checked BEFORE any allow paths (deny-overrides-all).
    """
    subject: str          # username or "*"
    resource: str
    namespace: str
    action: str

    @property
    def is_wildcard(self) -> bool:
        return self.subject == "*"


# AST node types for predicate parsing (used by parser.py)

@dataclass
class ASTNode:
    type: str  # "atom" | "AND" | "OR" | "THRESHOLD"


@dataclass
class ASTAtom(ASTNode):
    """A single attribute equality/inequality/in check."""
    type: str = "atom"
    attribute: str = ""
    operator: str = ""    # "==" | "!=" | "in"
    value: Any = None


@dataclass
class ASTBinary(ASTNode):
    """AND or OR combining two or more child expressions."""
    type: str = ""        # "AND" | "OR"
    children: list = field(default_factory=list)
    _paren: bool = field(default=False, compare=False, repr=False)
    """True when this node was the result of a parenthesized sub-expression.
    The parser uses this flag to prevent flattening across paren boundaries,
    which is required for the hash-consing 8-node property (Section 3.3)."""


@dataclass
class ASTThreshold(ASTNode):
    """At least k of the m children must evaluate to true."""
    type: str = "THRESHOLD"
    k: int = 0
    children: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# v2 compiled artifact types
# ---------------------------------------------------------------------------

@dataclass
class FastPath:
    """Fast-path descriptor Ξ_{n,r,a} — activation bits for each policy class.

    If a bit is False the entire policy class is skipped at runtime.
    """
    has_deny: bool = False
    has_acl: bool = False
    has_rbac: bool = False
    has_abac: bool = False


@dataclass
class PolicySummary:
    """Ψ_{n,r,a} — counts of each policy type for diagnostics."""
    acl_count: int = 0
    rbac_count: int = 0
    abac_count: int = 0
    deny_count: int = 0


@dataclass
class Token:
    """User authentication token τ = ⟨uid, R_u, G_u, A_u⟩.

    U-HAP trusts the token — authentication is completed before authorization.
    R_u and G_u both carry role/group memberships from the Kubernetes token;
    G_u is the raw groups list from the SAR spec while R_u may be pre-mapped.
    A_u holds user-specific attributes (merged with runtime context at eval time).
    """
    uid: str
    roles: List[str] = field(default_factory=list)    # R_u
    groups: List[str] = field(default_factory=list)   # G_u
    attributes: Dict[str, Any] = field(default_factory=dict)  # A_u


@dataclass
class CompiledGate:
    """A single ABAC gate compiled for index storage.

    Holds the shared DAG root, the set of attribute keys the predicate reads,
    and an estimated evaluation cost (used for cost-ordered evaluation).
    """
    root: Any           # AtomicCheck | GateNode | ThresholdGate (DAG node)
    required_attrs: Set[str] = field(default_factory=set)
    cost: int = 1


@dataclass
class CompiledArtifact:
    """C_{n,r,a} — all compiled indices for one (namespace, resource, action).

    Populated by the index compiler during Phase 2 and stored in the registry.
    Runtime evaluation only reads from these indices (no BFS, no graph traversal).
    """
    namespace: str
    resource: str
    action: str

    # Semantic graph reference (for audit/correctness; NOT used at runtime)
    graph: Any = None                        # PolicyGraph | None

    # Deny index: set of (scope_str, None) where scope = "user:alice" | "group:g" | "*"
    i_deny: Set[str] = field(default_factory=set)

    # ACL index: set of subject identifiers (uid or group name) authorized
    i_acl: Set[str] = field(default_factory=set)

    # RBAC index: set of role names (after transitive closure)
    i_rbac: Set[str] = field(default_factory=set)

    # Full role universe used to build b_rbac (all roles in namespace, including
    # hierarchy roles not in i_rbac).  Required so that the runtime bit-vector
    # reconstruction uses the same bit assignments as the compiler.
    role_universe: Set[str] = field(default_factory=set)

    # RBAC bit-vector (int with one bit per role in role_universe)
    b_rbac: int = 0

    # Pre-built RoleBitVector — stored at compile time so runtime never rebuilds it
    rbv: Any = None  # RoleBitVector | None

    # ABAC index: list of CompiledGate in insertion order (cost-sorted later)
    i_abac: List[CompiledGate] = field(default_factory=list)

    # Attribute-key index: attr_key -> list of CompiledGate that read it
    i_attr: Dict[str, List[CompiledGate]] = field(default_factory=dict)

    # Policy summary
    summary: Optional[PolicySummary] = None

    # Fast-path descriptor
    fast_path: Optional[FastPath] = None
