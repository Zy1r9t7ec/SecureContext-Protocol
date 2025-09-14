"""
Framework-specific integrations for the SCP SDK.
"""

# Import integrations based on availability
try:
    from .langchain import SCPTool, SCPChain
    __all__ = ['SCPTool', 'SCPChain']
except ImportError:
    __all__ = []

try:
    from .crewai import SCPCrewTool
    __all__.append('SCPCrewTool')
except ImportError:
    pass

try:
    from .autogen import SCPAutoGenTool
    __all__.append('SCPAutoGenTool')
except ImportError:
    pass

from .generic import GenericAgentAdapter
__all__.append('GenericAgentAdapter')