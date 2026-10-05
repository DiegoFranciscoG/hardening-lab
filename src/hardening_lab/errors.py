"""Errores del dominio. La CLI los traduce a mensajes claros sin trazas."""

from __future__ import annotations


class HardeningLabError(Exception):
    """Base de todos los errores esperados de la aplicación."""


class ConfigurationError(HardeningLabError):
    """Catálogo, excepciones o inventario inválidos o inconsistentes."""


class ParseError(HardeningLabError):
    """La salida de una herramienta no tiene el formato esperado."""


class StorageError(HardeningLabError):
    """Violación de las reglas de almacenamiento (run inmutable, historial con clave duplicada...)."""


class BaselineMissingError(HardeningLabError):
    """No hay línea base aprobada contra la cual comparar la deriva."""
