"""Rabbitmq module exception classes."""

from vism_lib.errors import VismException


class RabbitMQError(VismException):
    """Raised when a RabbitMQ error occurs."""
