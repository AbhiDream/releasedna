"""Trusted, code-registered ecosystem adapters. Package data cannot register code."""
from typing import Protocol
from app.core.safety import InspectionError


class RegistryAdapter(Protocol):
    ecosystem: str
    def validate(self,name: str,version: str) -> None: ...
    def fetch(self,fetcher,name: str,version: str) -> tuple[dict,bytes]: ...


class OfficialRegistry:
    def __init__(self,ecosystem): self.ecosystem=ecosystem
    def validate(self,name,version):
        from app.connectors.registry import _validate_builtin
        _validate_builtin(self.ecosystem,name,version)
    def fetch(self,fetcher,name,version):
        from app.connectors.registry import _fetch_builtin
        return _fetch_builtin(fetcher,self.ecosystem,name,version)


ADAPTERS={name:OfficialRegistry(name) for name in ('npm','pypi')}


def adapter_for(ecosystem):
    if ecosystem not in ADAPTERS: raise InspectionError('Unsupported registry adapter')
    return ADAPTERS[ecosystem]


def register_adapter(adapter: RegistryAdapter):
    if not adapter.ecosystem or adapter.ecosystem in ADAPTERS: raise ValueError('Adapter name already registered or empty')
    ADAPTERS[adapter.ecosystem]=adapter
