from __future__ import annotations

import ast
import runpy


def _patch_bandit_ast_compat() -> None:
    from bandit.core import context as bandit_context

    ast.Num = ast.Constant
    ast.Str = ast.Constant
    ast.Bytes = ast.Constant
    ast.NameConstant = ast.Constant
    ast.Constant.n = property(lambda self: self.value)
    ast.Constant.s = property(lambda self: self.value)

    def _get_literal_value(self, literal):
        if isinstance(literal, ast.Constant):
            return literal.value
        if isinstance(literal, ast.List):
            return [self._get_literal_value(item) for item in literal.elts]
        if isinstance(literal, ast.Tuple):
            return tuple(self._get_literal_value(item) for item in literal.elts)
        if isinstance(literal, ast.Set):
            return {self._get_literal_value(item) for item in literal.elts}
        if isinstance(literal, ast.Dict):
            return {
                self._get_literal_value(key): self._get_literal_value(value)
                for key, value in zip(literal.keys, literal.values)
            }
        if isinstance(literal, ast.Ellipsis):
            return None
        if isinstance(literal, ast.Name):
            return literal.id
        return None

    bandit_context.Context._get_literal_value = _get_literal_value


def main() -> None:
    _patch_bandit_ast_compat()
    runpy.run_module("bandit", run_name="__main__")


if __name__ == "__main__":
    main()
