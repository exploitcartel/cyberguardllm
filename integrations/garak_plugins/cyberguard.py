"""Alias so garak (>=0.13) can load the generator: it only resolves generators as garak.generators.<module>,
and reports plugin info by the class's own module, so the class must be defined here."""
from integrations.garak_generator import CyberGuardGenerator as _Base


class CyberGuardGenerator(_Base):
    """Sends garak prompts through CYBERGUARD LLM's own target configuration."""
