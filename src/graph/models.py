"""
Graph node and edge dataclasses for the U-HAP resource policy graph G_{n,r}.

Node types:
  RoleNode       - a role that has permissions on this resource (P_{n,r})
  ResourceNode   - the target resource (terminal for allow paths)
  DenyTerminal   - terminal for deny paths
  UserNode       - a specific user named in an ACL rule (U^acl_{n,r})

Edge types (5):
  HierEdge   - role inheritance: parent_role → child_role
  PermEdge   - RBAC permission: role --action--> resource
  GateEdge   - ABAC conditional: gate_root --action--> resource
  ACLEdge    - direct ACL: user --action--> resource
  DenyEdge   - deny: subject --action--> deny_terminal

The policy graph is an adjacency structure stored as:
  nodes: dict[node_id, node_object]
  edges: list[edge_object]

For fast lookup:
  deny_edges:     dict[(subject, action), DenyEdge]
  acl_edges:      dict[(subject, action), ACLEdge]
  perm_edges:     dict[(role, action), PermEdge]
  hier_edges:     dict[role, list[str]]    # parent -> [children]
  gate_edges:     dict[action, list[GateEdge]]
"""

from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RoleNode:
    """A role with permissions on this resource."""
    name: str
    node_type: str = "role"

    def __hash__(self):
        return hash(("role", self.name))

    def __eq__(self, other):
        return isinstance(other, RoleNode) and self.name == other.name


@dataclass(frozen=True)
class ResourceNode:
    """The target resource — terminal for all allow paths."""
    name: str
    namespace: str
    node_type: str = "resource"

    def __hash__(self):
        return hash(("resource", self.namespace, self.name))

    def __eq__(self, other):
        return (isinstance(other, ResourceNode)
                and self.name == other.name
                and self.namespace == other.namespace)


@dataclass(frozen=True)
class DenyTerminal:
    """Sink node for all deny paths."""
    node_type: str = "deny_terminal"

    def __hash__(self):
        return hash("deny_terminal")

    def __eq__(self, other):
        return isinstance(other, DenyTerminal)


@dataclass(frozen=True)
class UserNode:
    """A specific user named in an ACL rule."""
    name: str
    node_type: str = "user"

    def __hash__(self):
        return hash(("user", self.name))

    def __eq__(self, other):
        return isinstance(other, UserNode) and self.name == other.name


# ---------------------------------------------------------------------------
# Edge types
# ---------------------------------------------------------------------------

@dataclass
class HierEdge:
    """Role inheritance: parent_role -> child_role (no action label)."""
    parent: str    # role name
    child: str     # role name
    edge_type: str = "hier"


@dataclass
class PermEdge:
    """RBAC unconditional permission: role --action--> resource."""
    role: str
    resource: str
    namespace: str
    action: str
    edge_type: str = "perm"


@dataclass
class GateEdge:
    """ABAC conditional permission: gate_root --action--> resource.

    gate_root is an AtomicCheck or GateNode from the shared DAG.
    """
    gate_root: Any    # AtomicCheck | GateNode | ThresholdGate
    resource: str
    namespace: str
    action: str
    edge_type: str = "gate"


@dataclass
class ACLEdge:
    """Direct ACL permission: subject --action--> resource."""
    subject: str
    resource: str
    namespace: str
    action: str
    edge_type: str = "acl"


@dataclass
class DenyEdge:
    """Unconditional deny: subject (or *) --action--> deny_terminal."""
    subject: str      # username or "*"
    resource: str
    namespace: str
    action: str
    edge_type: str = "deny"

    @property
    def is_wildcard(self) -> bool:
        return self.subject == "*"


# ---------------------------------------------------------------------------
# Policy graph
# ---------------------------------------------------------------------------

@dataclass
class PolicyGraph:
    """
    Resource-scoped policy graph G_{n,r}.

    Stores edges in both a flat list and fast-lookup dicts for O(1) access
    during evaluation.
    """
    namespace: str
    resource: str

    # Fast-lookup structures (built during graph construction)
    # deny_edges: (subject, action) -> DenyEdge
    deny_edges: dict = field(default_factory=dict)

    # acl_edges: (subject, action) -> ACLEdge
    acl_edges: dict = field(default_factory=dict)

    # perm_edges: (role, action) -> PermEdge
    perm_edges: dict = field(default_factory=dict)

    # hier_edges: parent_role -> list of child_role names
    hier_edges: dict = field(default_factory=dict)

    # gate_edges: action -> list of GateEdge
    gate_edges: dict = field(default_factory=dict)

    def add_hier_edge(self, parent: str, child: str) -> None:
        if parent not in self.hier_edges:
            self.hier_edges[parent] = []
        if child not in self.hier_edges[parent]:
            self.hier_edges[parent].append(child)

    def add_perm_edge(self, role: str, action: str) -> None:
        self.perm_edges[(role, action)] = PermEdge(
            role=role, resource=self.resource,
            namespace=self.namespace, action=action
        )

    def add_gate_edge(self, gate_root: Any, action: str) -> None:
        if action not in self.gate_edges:
            self.gate_edges[action] = []
        self.gate_edges[action].append(
            GateEdge(gate_root=gate_root, resource=self.resource,
                     namespace=self.namespace, action=action)
        )

    def add_acl_edge(self, subject: str, action: str) -> None:
        self.acl_edges[(subject, action)] = ACLEdge(
            subject=subject, resource=self.resource,
            namespace=self.namespace, action=action
        )

    def add_deny_edge(self, subject: str, action: str) -> None:
        self.deny_edges[(subject, action)] = DenyEdge(
            subject=subject, resource=self.resource,
            namespace=self.namespace, action=action
        )

    def has_deny(self, subject: str, action: str) -> bool:
        """Return True if there is a deny edge for this subject or wildcard."""
        return ((subject, action) in self.deny_edges
                or ("*", action) in self.deny_edges)

    def has_acl(self, subject: str, action: str) -> bool:
        return (subject, action) in self.acl_edges

    def has_perm(self, role: str, action: str) -> bool:
        return (role, action) in self.perm_edges

    def get_children(self, role: str) -> list:
        """Return list of child role names for hierarchy BFS."""
        return self.hier_edges.get(role, [])

    def get_gate_edges(self, action: str) -> list:
        return self.gate_edges.get(action, [])
