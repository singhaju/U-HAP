"""
Predicate parser for U-HAP ABAC policy DSL.

Grammar (with correct precedence: AND binds tighter than OR):
    predicate   := expr
    expr        := and_expr (OR and_expr)*
    and_expr    := term (AND term)*
    term        := atom | '(' expr ')' | threshold
    atom        := ATTRIBUTE OPERATOR VALUE
    threshold   := 'ATLEAST' '(' NUMBER ',' expr (',' expr)+ ')'
    ATTRIBUTE   := [a-zA-Z_][a-zA-Z0-9_]*
    OPERATOR    := '==' | '!=' | 'in'
    VALUE       := STRING_LITERAL | NUMBER | LIST_LITERAL

Token types:
    ATOM_ATTR   - attribute name (identifier)
    OP          - == | != | in
    VALUE       - string/number/list value
    AND         - keyword AND
    OR          - keyword OR
    ATLEAST     - keyword ATLEAST
    LPAREN      - (
    RPAREN      - )
    COMMA       - ,
    EOF         - end of input

Returns AST nodes from dsl.models:
    ASTAtom, ASTBinary, ASTThreshold
"""

import re
from dataclasses import dataclass, field
from typing import Any, List

from dsl.models import ASTAtom, ASTBinary, ASTThreshold


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

# Token type constants
TOK_ATTR    = "ATTR"        # identifier not matching a keyword
TOK_OP      = "OP"          # == | != | in
TOK_VALUE   = "VALUE"       # string or number literal
TOK_AND     = "AND"
TOK_OR      = "OR"
TOK_ATLEAST = "ATLEAST"
TOK_LPAREN  = "LPAREN"
TOK_RPAREN  = "RPAREN"
TOK_LBRACKET = "LBRACKET"
TOK_RBRACKET = "RBRACKET"
TOK_COMMA   = "COMMA"
TOK_EOF     = "EOF"


@dataclass
class Token:
    type: str
    value: Any
    pos: int


def tokenize(text: str) -> List[Token]:
    """Convert a predicate string into a list of tokens."""
    tokens = []
    pos = 0
    n = len(text)

    while pos < n:
        # Skip whitespace
        if text[pos].isspace():
            pos += 1
            continue

        # Single-quoted string literal
        if text[pos] == "'":
            end = text.index("'", pos + 1)
            tokens.append(Token(TOK_VALUE, text[pos+1:end], pos))
            pos = end + 1
            continue

        # Double-quoted string literal
        if text[pos] == '"':
            end = text.index('"', pos + 1)
            tokens.append(Token(TOK_VALUE, text[pos+1:end], pos))
            pos = end + 1
            continue

        # Two-character operators
        if text[pos:pos+2] in ("==", "!="):
            tokens.append(Token(TOK_OP, text[pos:pos+2], pos))
            pos += 2
            continue

        # Single-char tokens
        if text[pos] == "(":
            tokens.append(Token(TOK_LPAREN, "(", pos))
            pos += 1
            continue
        if text[pos] == ")":
            tokens.append(Token(TOK_RPAREN, ")", pos))
            pos += 1
            continue
        if text[pos] == "[":
            tokens.append(Token(TOK_LBRACKET, "[", pos))
            pos += 1
            continue
        if text[pos] == "]":
            tokens.append(Token(TOK_RBRACKET, "]", pos))
            pos += 1
            continue
        if text[pos] == ",":
            tokens.append(Token(TOK_COMMA, ",", pos))
            pos += 1
            continue

        # Number literal (integer or float)
        m = re.match(r"[0-9]+(?:\.[0-9]+)?", text[pos:])
        if m:
            raw = m.group(0)
            val = float(raw) if "." in raw else int(raw)
            tokens.append(Token(TOK_VALUE, val, pos))
            pos += len(raw)
            continue

        # Identifier or keyword
        m = re.match(r"[a-zA-Z_][a-zA-Z0-9_\-]*", text[pos:])
        if m:
            word = m.group(0)
            if word == "AND":
                tokens.append(Token(TOK_AND, "AND", pos))
            elif word == "OR":
                tokens.append(Token(TOK_OR, "OR", pos))
            elif word == "ATLEAST":
                tokens.append(Token(TOK_ATLEAST, "ATLEAST", pos))
            elif word == "in":
                tokens.append(Token(TOK_OP, "in", pos))
            else:
                tokens.append(Token(TOK_ATTR, word, pos))
            pos += len(word)
            continue

        raise SyntaxError(
            f"Unexpected character {text[pos]!r} at position {pos} in: {text!r}"
        )

    tokens.append(Token(TOK_EOF, None, n))
    return tokens


# ---------------------------------------------------------------------------
# Recursive descent parser
# ---------------------------------------------------------------------------

class Parser:
    """Recursive descent parser for predicate expressions.

    Precedence (low to high):
        OR  (lowest)
        AND
        atom / parenthesized / ATLEAST  (highest)
    """

    def __init__(self, tokens: List[Token]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _consume(self, expected_type: str = None) -> Token:
        tok = self._tokens[self._pos]
        if expected_type and tok.type != expected_type:
            raise SyntaxError(
                f"Expected {expected_type}, got {tok.type!r} ({tok.value!r}) "
                f"at position {tok.pos}"
            )
        self._pos += 1
        return tok

    # expr := and_expr (OR and_expr)*
    def parse_expr(self):
        left = self._parse_and_expr()
        while self._peek().type == TOK_OR:
            self._consume(TOK_OR)
            right = self._parse_and_expr()
            # Flatten consecutive ORs into a single ASTBinary, but only when
            # left was NOT a parenthesized sub-expression (to preserve
            # structural identity for hash-consing sub-expression sharing).
            if (isinstance(left, ASTBinary) and left.type == "OR"
                    and not getattr(left, '_paren', False)):
                left.children.append(right)
            else:
                left = ASTBinary(type="OR", children=[left, right])
        return left

    # and_expr := term (AND term)*
    def _parse_and_expr(self):
        left = self._parse_term()
        while self._peek().type == TOK_AND:
            self._consume(TOK_AND)
            right = self._parse_term()
            # Flatten consecutive ANDs into a single ASTBinary, but only when
            # left was NOT a parenthesized sub-expression (to preserve
            # structural identity for hash-consing sub-expression sharing).
            if (isinstance(left, ASTBinary) and left.type == "AND"
                    and not getattr(left, '_paren', False)):
                left.children.append(right)
            else:
                left = ASTBinary(type="AND", children=[left, right])
        return left

    # term := atom | '(' expr ')' | ATLEAST(...)
    def _parse_term(self):
        tok = self._peek()

        if tok.type == TOK_LPAREN:
            self._consume(TOK_LPAREN)
            node = self.parse_expr()
            self._consume(TOK_RPAREN)
            # Mark as parenthesized so the containing and_expr/expr does NOT
            # flatten this node into a sibling list. This preserves structural
            # sub-expression identity needed for hash consing.
            if isinstance(node, ASTBinary):
                node._paren = True
            return node

        if tok.type == TOK_ATLEAST:
            return self._parse_threshold()

        if tok.type == TOK_ATTR:
            return self._parse_atom()

        raise SyntaxError(
            f"Unexpected token {tok.type!r} ({tok.value!r}) at position {tok.pos}"
        )

    # atom := ATTRIBUTE OPERATOR VALUE
    def _parse_atom(self):
        attr_tok = self._consume(TOK_ATTR)
        op_tok = self._consume(TOK_OP)

        # VALUE may be a string/number literal, or a list literal [...]
        if self._peek().type == TOK_LBRACKET:
            value = self._parse_list_literal()
        else:
            value_tok = self._consume(TOK_VALUE)
            value = value_tok.value

        return ASTAtom(attribute=attr_tok.value, operator=op_tok.value, value=value)

    def _parse_list_literal(self):
        self._consume(TOK_LBRACKET)
        items = []
        while self._peek().type != TOK_RBRACKET:
            tok = self._consume(TOK_VALUE)
            items.append(tok.value)
            if self._peek().type == TOK_COMMA:
                self._consume(TOK_COMMA)
        self._consume(TOK_RBRACKET)
        return items

    # threshold := ATLEAST '(' NUMBER ',' expr (',' expr)+ ')'
    def _parse_threshold(self):
        self._consume(TOK_ATLEAST)
        self._consume(TOK_LPAREN)
        k_tok = self._consume(TOK_VALUE)
        k = int(k_tok.value)
        self._consume(TOK_COMMA)
        children = [self.parse_expr()]
        while self._peek().type == TOK_COMMA:
            self._consume(TOK_COMMA)
            children.append(self.parse_expr())
        self._consume(TOK_RPAREN)
        if len(children) < 2:
            raise SyntaxError("ATLEAST requires at least 2 sub-expressions")
        return ASTThreshold(k=k, children=children)

    def parse(self):
        node = self.parse_expr()
        self._consume(TOK_EOF)
        return node


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_predicate(text: str):
    """Parse a predicate string into an AST.

    Returns an ASTAtom, ASTBinary, or ASTThreshold node.
    Raises SyntaxError on invalid input.
    """
    tokens = tokenize(text.strip())
    parser = Parser(tokens)
    return parser.parse()
