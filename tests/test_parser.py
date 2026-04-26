"""
Tests for Step 2: Predicate parser.
Verifies parsing of atoms, AND/OR with correct precedence, parentheses,
ATLEAST thresholds, and list literals.
"""
import pytest
from dsl.parser import parse_predicate
from dsl.models import ASTAtom, ASTBinary, ASTThreshold


class TestAtomParsing:
    def test_simple_equality(self):
        ast = parse_predicate("net == 'on-premise'")
        assert isinstance(ast, ASTAtom)
        assert ast.attribute == "net"
        assert ast.operator == "=="
        assert ast.value == "on-premise"

    def test_inequality(self):
        ast = parse_predicate("time != 'after-hours'")
        assert isinstance(ast, ASTAtom)
        assert ast.operator == "!="

    def test_in_operator(self):
        ast = parse_predicate("role in ['admin', 'ops']")
        assert isinstance(ast, ASTAtom)
        assert ast.operator == "in"
        assert ast.value == ["admin", "ops"]

    def test_numeric_value(self):
        ast = parse_predicate("level == 3")
        assert isinstance(ast, ASTAtom)
        assert ast.value == 3

    def test_double_quoted_string(self):
        ast = parse_predicate('dept == "engineering"')
        assert isinstance(ast, ASTAtom)
        assert ast.value == "engineering"

    def test_hyphenated_attribute(self):
        # attribute names may contain hyphens in some policy files
        ast = parse_predicate("dept-id == 'eng'")
        assert isinstance(ast, ASTAtom)
        assert ast.attribute == "dept-id"


class TestAndOrPrecedence:
    """AND must bind tighter than OR (standard boolean precedence)."""

    def test_simple_and(self):
        ast = parse_predicate("net == 'on-premise' AND time == 'business-hours'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "AND"
        assert len(ast.children) == 2
        assert all(isinstance(c, ASTAtom) for c in ast.children)

    def test_simple_or(self):
        ast = parse_predicate("dept == 'engineering' OR dept == 'security'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "OR"
        assert len(ast.children) == 2

    def test_and_or_precedence(self):
        # a AND b OR c should parse as (a AND b) OR c
        ast = parse_predicate("net == 'on-premise' AND time == 'business-hours' OR dept == 'engineering'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "OR"
        # Left child should be AND(net, time)
        left = ast.children[0]
        assert isinstance(left, ASTBinary)
        assert left.type == "AND"
        # Right child should be the atom dept
        right = ast.children[1]
        assert isinstance(right, ASTAtom)
        assert right.attribute == "dept"

    def test_or_and_precedence(self):
        # a OR b AND c should parse as a OR (b AND c)
        ast = parse_predicate("net == 'on-premise' OR time == 'business-hours' AND dept == 'engineering'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "OR"
        left = ast.children[0]
        assert isinstance(left, ASTAtom)
        assert left.attribute == "net"
        right = ast.children[1]
        assert isinstance(right, ASTBinary)
        assert right.type == "AND"

    def test_chained_and(self):
        # a AND b AND c → single AND with 3 children (flattened)
        ast = parse_predicate("a == '1' AND b == '2' AND c == '3'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "AND"
        assert len(ast.children) == 3

    def test_chained_or(self):
        ast = parse_predicate("a == '1' OR b == '2' OR c == '3'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "OR"
        assert len(ast.children) == 3


class TestParentheses:
    def test_parens_override_precedence(self):
        # (a OR b) AND c  →  AND(OR(a,b), c)
        ast = parse_predicate("(net == 'on-premise' OR net == 'vpn') AND time == 'business-hours'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "AND"
        inner = ast.children[0]
        assert isinstance(inner, ASTBinary)
        assert inner.type == "OR"
        assert len(inner.children) == 2

    def test_nested_parens(self):
        ast = parse_predicate("((net == 'on-premise')) AND time == 'business-hours'")
        assert isinstance(ast, ASTBinary)
        assert ast.type == "AND"
        inner = ast.children[0]
        assert isinstance(inner, ASTAtom)
        assert inner.attribute == "net"


class TestThreshold:
    def test_atleast_basic(self):
        ast = parse_predicate(
            "ATLEAST(2, net == 'on-premise', time == 'business-hours', dept == 'engineering')"
        )
        assert isinstance(ast, ASTThreshold)
        assert ast.k == 2
        assert len(ast.children) == 3
        assert all(isinstance(c, ASTAtom) for c in ast.children)

    def test_atleast_with_compound_children(self):
        ast = parse_predicate(
            "ATLEAST(2, net == 'on-premise', time == 'business-hours' AND dept == 'engineering', clearance == 'top-secret')"
        )
        assert isinstance(ast, ASTThreshold)
        assert ast.k == 2
        # Second child should be an AND node
        assert isinstance(ast.children[1], ASTBinary)
        assert ast.children[1].type == "AND"

    def test_atleast_requires_two_exprs(self):
        with pytest.raises(SyntaxError):
            parse_predicate("ATLEAST(1, net == 'on-premise')")


class TestEdgeCases:
    def test_whitespace_variations(self):
        ast1 = parse_predicate("net=='on-premise'")
        ast2 = parse_predicate("  net  ==  'on-premise'  ")
        assert isinstance(ast1, ASTAtom)
        assert isinstance(ast2, ASTAtom)
        assert ast1.attribute == ast2.attribute == "net"
        assert ast1.value == ast2.value == "on-premise"

    def test_invalid_token_raises(self):
        with pytest.raises(SyntaxError):
            parse_predicate("@invalid")

    def test_missing_value_raises(self):
        with pytest.raises((SyntaxError, IndexError, Exception)):
            parse_predicate("net ==")

    def test_complex_mixed(self):
        # From the project plan examples
        ast = parse_predicate(
            "net == 'on-premise' AND time == 'business-hours'"
        )
        assert ast.type == "AND"
        attrs = [c.attribute for c in ast.children]
        assert "net" in attrs
        assert "time" in attrs


class TestProjectPlanExamples:
    """Verify the exact examples from Section 4.2 of the project plan."""

    def test_p1_a1_or_a2(self):
        # P1: a1 ∨ a2  where a1=net=='on-premise', a2=time=='business-hours'
        ast = parse_predicate("net == 'on-premise' OR time == 'business-hours'")
        assert ast.type == "OR"
        assert len(ast.children) == 2

    def test_p2_a1_or_a2_and_a2_and_a3(self):
        # P2: (a1 ∨ a2) ∧ (a2 ∧ a3)
        ast = parse_predicate(
            "(net == 'on-premise' OR time == 'business-hours') AND "
            "(time == 'business-hours' AND dept == 'engineering')"
        )
        assert ast.type == "AND"
        assert ast.children[0].type == "OR"
        assert ast.children[1].type == "AND"

    def test_p3_a2_and_a3(self):
        # P3: a2 ∧ a3
        ast = parse_predicate("time == 'business-hours' AND dept == 'engineering'")
        assert ast.type == "AND"

    def test_p4_a2_and_a3_and_a4(self):
        # P4: (a2 ∧ a3) ∧ a4
        ast = parse_predicate(
            "(time == 'business-hours' AND dept == 'engineering') AND clearance == 'top-secret'"
        )
        assert ast.type == "AND"

    def test_abac_on_premise_and_business_hours(self):
        ast = parse_predicate("net == 'on-premise' AND time == 'business-hours'")
        assert ast.type == "AND"
        assert ast.children[0].attribute == "net"
        assert ast.children[1].attribute == "time"
