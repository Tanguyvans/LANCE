"""Measure LANCE's source layout without importing or executing application code.

Run with Python >= 3.12, from any directory:
    python scripts/analysis/code_organisation.py --output /tmp/organisation.json

Import edges are syntactic possibilities, not evidence that a runtime cycle fails.
The module/function scope is lexical: a function can be called during module load.
Function spans include comments, blank lines and nested definitions.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def module_name(path: str) -> str:
    name = path.removesuffix(".py").replace("/", ".")
    return name.removesuffix(".__init__")


def components(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan's strongly connected components, excluding singleton self-edges."""
    index = 0
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    pending: set[str] = set()
    result: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = low[node] = index
        index += 1
        stack.append(node)
        pending.add(node)
        for target in sorted(graph[node]):
            if target not in indices:
                visit(target)
                low[node] = min(low[node], low[target])
            elif target in pending:
                low[node] = min(low[node], indices[target])
        if low[node] == indices[node]:
            group: list[str] = []
            while True:
                target = stack.pop()
                pending.remove(target)
                group.append(target)
                if target == node:
                    break
            if len(group) > 1:
                result.append(sorted(group))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(result, key=lambda group: (-len(group), group))


class SourceVisitor(ast.NodeVisitor):
    def __init__(self, module: str, is_package: bool, modules: set[str]):
        self.module = module
        self.package = module if is_package else module.rpartition(".")[0]
        self.modules = modules
        self.names: list[str] = []
        self.function_depth = 0
        self.type_checking_depth = 0
        self.imports: list[dict] = []
        self.functions: list[dict] = []
        self.classes: list[dict] = []
        self.global_statements = 0

    def add_import(self, target: str, line: int) -> None:
        if target not in self.modules or target == self.module:
            return
        scope = "type_checking" if self.type_checking_depth else (
            "function" if self.function_depth else "module"
        )
        self.imports.append({"target": target, "line": line, "scope": scope})

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.add_import(alias.name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            parts = self.package.split(".")
            if node.level > len(parts):
                return
            prefix = ".".join(parts[:len(parts) - node.level + 1])
            base = ".".join(part for part in (prefix, node.module) if part)
        else:
            base = node.module or ""
        self.add_import(base, node.lineno)
        for alias in node.names:
            self.add_import(f"{base}.{alias.name}", node.lineno)

    def visit_If(self, node: ast.If) -> None:
        test = node.test
        typing_only = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        self.visit(test)
        self.type_checking_depth += int(typing_only)
        for child in node.body:
            self.visit(child)
        self.type_checking_depth -= int(typing_only)
        for child in node.orelse:
            self.visit(child)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes.append({"name": node.name, "line": node.lineno,
                             "bases": [ast.unparse(base) for base in node.bases]})
        self.names.append(node.name)
        self.generic_visit(node)
        self.names.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = node.args
        parameters = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
        parameters += int(args.vararg is not None) + int(args.kwarg is not None)
        self.functions.append({"name": ".".join([*self.names, node.name]),
                               "line": node.lineno, "end": node.end_lineno,
                               "span": node.end_lineno - node.lineno + 1,
                               "parameters_including_self": parameters,
                               "nested": self.function_depth > 0})
        # Decorators and default expressions execute in the enclosing scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*args.defaults, *filter(None, args.kw_defaults)]:
            self.visit(default)
        self.names.append(node.name)
        self.function_depth += 1
        for child in node.body:
            self.visit(child)
        self.function_depth -= 1
        self.names.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Global(self, node: ast.Global) -> None:
        self.global_statements += 1


def audit() -> dict:
    listing = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    ).decode().split("\0")
    paths = sorted({path for path in listing if path.endswith(".py")
                    and path.split("/")[0] in {"src", "scripts", "model_training"}
                    and "/tests/" not in path and not path.startswith("scripts/analysis/")
                    and (ROOT / path).is_file()})
    modules = {module_name(path) for path in paths}
    files = []
    digest = hashlib.sha256()
    for path in paths:
        raw = (ROOT / path).read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        digest.update(f"{path}\0{sha}\n".encode())
        source = raw.decode("utf-8")
        visitor = SourceVisitor(module_name(path), path.endswith("/__init__.py"), modules)
        visitor.visit(ast.parse(source, filename=path))
        files.append({"path": path, "module": module_name(path), "sha256": sha,
                      "lines": len(source.splitlines()), "imports": visitor.imports,
                      "functions": visitor.functions, "classes": visitor.classes,
                      "global_statements": visitor.global_statements})
    graphs = {}
    for mode in ("module", "all_non_typing"):
        graphs[mode] = {
            row["module"]: {edge["target"] for edge in row["imports"]
                            if edge["scope"] == "module" or (
                                mode == "all_non_typing" and edge["scope"] == "function")}
            for row in files
        }
    graph = graphs["all_non_typing"]
    incoming = Counter(target for targets in graph.values() for target in targets)
    for row in files:
        row["internal_fan_out"] = len(graph[row["module"]])
        row["internal_fan_in"] = incoming[row["module"]]
    tests = [path for path in listing if path.endswith(".py") and (
        path.startswith("tests/") or path.startswith("model_training/tests/"))]
    js_path = "src/static/app.js"
    js = (ROOT / js_path).read_bytes()
    return {
        "method": "AST Python 3.12+; explicit imports with lexical scopes, not execution order; physical line spans",
        "exclusions": ["tests from production metrics", "ignored files", "scripts/analysis/",
                       "JavaScript dependencies and vendor assets",
                       "implicit parent-package imports and dynamic import calls"],
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        "python_sources_sha256": digest.hexdigest(),
        "source_files": len(files), "python_lines": sum(row["lines"] for row in files),
        "test_files": len(set(tests)),
        "static_app": {"path": js_path, "lines": len(js.decode().splitlines()),
                       "sha256": hashlib.sha256(js).hexdigest()},
        "components": {mode: components(g) for mode, g in graphs.items()},
        "files": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "files"}, indent=2))


if __name__ == "__main__":
    main()
