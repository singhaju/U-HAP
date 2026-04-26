"""
U-HAP compiler package — Phase 2 policy compilation.

Modules:
  role_closure    - transitive closure of role hierarchies
  bitvector       - role bit-vector encoding
  graph_builder   - semantic graph G_{n,r} construction
  index_compiler  - compile G_{n,r} -> C_{n,r,a} indices
  registry        - 3-level in-memory registry[ns][res][action]
"""
