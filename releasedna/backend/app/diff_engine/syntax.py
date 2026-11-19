"""Bounded syntax evidence, not a proof of arbitrary program equivalence."""
import ast
import difflib
import re
from tree_sitter import Language, Parser
import tree_sitter_javascript

JS=Language(tree_sitter_javascript.language())
LIMIT=256000
JS_SUFFIXES={'.js','.mjs','.cjs','.jsx','.ts','.tsx'}
ESCAPE_RE=re.compile(rb'\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})')
ESCAPES_PER_KB=12
MIN_ESCAPES=8


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


def escape_density(data,path,suffix):
    """Count hex/unicode escapes in parsed JS string literals only."""
    if path.lower().endswith('.d.ts') or suffix not in JS_SUFFIXES:
        return {'eligible':False,'count':0,'per_kb':0.0,'evidence':[]}
    root=javascript(data)
    if root is None: return None
    matches=[]; stack=[root]
    while stack:
        node=stack.pop()
        if node.type=='escape_sequence':
            raw=data[node.start_byte:node.end_byte]
            if ESCAPE_RE.fullmatch(raw):
                start=node.start_byte
                matches.append({'line':data.count(b'\n',0,start)+1,'byte_offset':start,
                                'text':data[max(0,start-48):min(len(data),start+len(raw)+64)].decode('utf-8',errors='replace')})
        stack.extend(reversed(node.children))
    count=len(matches)
    density=count*1024/max(len(data),1)
    return {'eligible':True,'count':count,'per_kb':density,'evidence':matches[:8]}


def _signature(node,data):
    children=tuple(value for child in node.children if (value:=_signature(child,data)) is not None)
    if node.type=='comment': return None
    return (node.type,children,data[node.start_byte:node.end_byte] if not node.children else b'')


def _regex_exec_call(node):
    if node.type!='call_expression' or len(node.named_children)!=2: return False
    callee,args=node.named_children
    if callee.type!='member_expression' or len(callee.named_children)!=2: return False
    receiver,property_node=callee.named_children
    if receiver.type!='regex' or property_node.type!='property_identifier': return False
    if args.type!='arguments' or len(args.named_children)!=1 or args.named_children[0].type!='string': return False
    return True


def _pure_regex_exec_statement(node):
    if node.type=='expression_statement':
        return len(node.named_children)==1 and _regex_exec_call(node.named_children[0])
    if node.type in {'lexical_declaration','variable_declaration'}:
        declarations=[child for child in node.named_children if child.type=='variable_declarator']
        if len(declarations)!=1: return False
        values=[child for child in declarations[0].named_children if child.type not in {'identifier','type_annotation'}]
        return len(values)==1 and _regex_exec_call(values[0])
    return False


def regex_exec_only_addition(artifact,source,suffix):
    """Explain only inserted, top-level regex.exec(string-literal) statements."""
    if suffix not in {'.js','.mjs','.cjs'}: return False
    artifact_root,source_root=javascript(artifact),javascript(source)
    if artifact_root is None or source_root is None: return False
    before=[node for node in source_root.named_children if node.type!='comment']
    after=[node for node in artifact_root.named_children if node.type!='comment']
    matcher=difflib.SequenceMatcher(None,[_signature(n,source) for n in before],
                                    [_signature(n,artifact) for n in after],autojunk=False)
    additions=[]
    for operation,_,_,start,end in matcher.get_opcodes():
        if operation=='insert': additions.extend(after[start:end])
        elif operation!='equal': return False
    return bool(additions) and all(_pure_regex_exec_statement(node) for node in additions)
