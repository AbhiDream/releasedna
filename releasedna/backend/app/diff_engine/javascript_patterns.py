"""Versioned list of high-signal static JavaScript review patterns.

These small structural indicators are scored as evidence, never as a malware verdict.
They intentionally avoid generic minification and ordinary _0x substring matches.
"""

OBFUSCATION_RULES = (
    'OBFUSCATED_DYNAMIC_EXECUTION',
    'OBFUSCATED_MODULE_LOAD',
    'BROWSER_API_HOOK',
    'OBFUSCATOR_IDENTIFIER',
)
