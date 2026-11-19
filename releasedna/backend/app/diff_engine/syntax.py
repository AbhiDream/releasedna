"""Bounded syntax evidence, not a proof of arbitrary program equivalence."""
import ast
from tree_sitter import Language, Parser
import tree_sitter_javascript

JS=Language(tree_sitter_javascript.language())
LIMIT=256000


def javascript(data):
    if len(data)>LIMIT: return None
    tree=Parser(JS).parse(data)
    return None if tree.root_node.has_error else tree.root_node


def signature(data,suffix):
    if len(data)>LIMIT: return None
    try:
        if suffix=='.py': return ast.dump(ast.parse(data),include_attributes=False)
        if suffix not in {'.js','.mjs','.cjs'}: return None
        root=javascript(data)
        if root is None: return None
        result=[]; stack=[root]; budget=100000
        while stack:
            item=stack.pop(); budget-=1
            if budget<0: return None
            if item.type=='comment': continue
            # Keep punctuation and literal bytes: ASI/string changes must not disappear.
            result.append((item.type,item.child_count,data[item.start_byte:item.end_byte] if not item.child_count else b''))
            stack.extend(reversed([c for c in item.children if c.type!='comment']))
            # Child counts exclude comments as well.
            if item.child_count: result[-1]=(item.type,len([c for c in item.children if c.type!='comment']),b'')
        return result
    except (SyntaxError,ValueError,UnicodeError,RecursionError): return None


def equivalent(a,b,suffix):
    left=signature(a,suffix)
    return left is not None and left==signature(b,suffix)


def code_after_map(data,suffix):
    if suffix not in {'.js','.mjs','.cjs'}: return []
    root=javascript(data)
    if root is None: return []
    mapping=False; evidence=[]
    for child in root.children:
        raw=data[child.start_byte:child.end_byte]
        if child.type=='comment':
            if raw.lstrip().startswith((b'//# sourceMappingURL=',b'//@ sourceMappingURL=')): mapping=True
        elif mapping:
            evidence.append({'line':child.start_point.row+1,'text':raw[:400].decode('utf-8',errors='replace')})
    return evidence[:8]
