"""Trusted extension point for static build explanations; never runs builds."""
from typing import Protocol
from app.diff_engine.generated import GeneratedContext


class BuildAdapter(Protocol):
    def explain(self,path: str) -> dict | None: ...


BUILD_ADAPTERS=[GeneratedContext]


class BuildContext:
    def __init__(self,artifact,source):
        self.adapters=[factory(artifact,source) for factory in BUILD_ADAPTERS]
        self.npm=self.adapters[0]
        self.maps=self.npm.maps
        self.artifact,self.source=artifact,source
        self.metadata,self.build=self.npm.metadata,self.npm.build

    def explain(self,path):
        for adapter in self.adapters:
            evidence=adapter.explain(path)
            if evidence:
                return {**evidence,'equivalence_verified':False}
        return None
