"""
Gossipsub protocol

- Parameters for gossipsub operation.
- Message ID computation based on topic and message data, with snappy decompression handling.
"""

import hashlib
from typing import Callable, Optional

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)
from lean_spec.types import StrictBaseModel


class GossipsubParameters(StrictBaseModel):
    """A model holding the canonical gossipsub parameters."""

    protocol_id: str = "/meshsub/1.0.0"
    """The protocol ID for gossip messages."""

    d: int = 8
    """The target number of peers for a stable gossip mesh topic."""

    d_low: int = 6
    """
    The low watermark for the number of peers in a stable gossip mesh topic.
    """

    d_high: int = 12
    """
    The high watermark for the number of peers in a stable gossip mesh topic.
    """

    d_lazy: int = 6
    """The target number of peers for gossip-only connections."""

    heartbeat_interval_secs: float = 0.7
    """The frequency of the gossipsub heartbeat in seconds."""

    fanout_ttl_secs: int = 60
    """The time-to-live for fanout maps in seconds."""

    mcache_len: int = 6
    """The number of history windows to retain full messages in the cache."""

    mcache_gossip: int = 3
    """The number of history windows to gossip about."""

    seen_ttl_secs: int = (
        DEVNET_CONFIG.second_per_slot * DEVNET_CONFIG.justification_lookback_slots * 2
    )
    """
    The expiry time in seconds for the cache of seen message IDs.

    This is calculated as SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2.
    """


_MessageId = NewType("MessageId", bytes)
"""Static analysis to prevent accidental misuse of generic bytes."""

MessageId = Annotated[_MessageId, Field(min_length=20, max_length=20)]
"""A 20-byte ID for gossipsub messages."""


def compute_message_id(
    topic: bytes,
    data: bytes,
    snappy_decompress: Optional[Callable[[bytes], bytes]] = None,
) -> MessageId:
    """
    Compute the message ID for a gossipsub message.

    The message ID is computed based on whether the data can be
    successfully decompressed with snappy.

    Args:
        topic: The topic byte string.
        data: The raw message data.
        snappy_decompress: Optional snappy decompression function.
            If not provided, treats data as invalid snappy.

    Returns:
        A 20-byte message ID.
    """
    if snappy_decompress is not None:
        try:
            # Try to decompress the data with snappy
            decompressed_data = snappy_decompress(data)
            # Valid snappy decompression - use valid domain
            return _compute_message_id_with_domain(
                MESSAGE_DOMAIN_VALID_SNAPPY, topic, decompressed_data
            )
        except Exception:
            # Invalid snappy decompression - use invalid domain
            pass

    # No decompressor provided or decompression failed - use invalid domain
    return _compute_message_id_with_domain(MESSAGE_DOMAIN_INVALID_SNAPPY, topic, data)


def _compute_message_id_with_domain(domain: bytes, topic: bytes, message_data: bytes) -> MessageId:
    """
    Compute message ID with the given domain.

    Computes SHA256(domain + uint64_le(len(topic)) + topic + message_data)[:20].

    Args:
        domain: The 4-byte domain for message-id isolation.
        topic: The topic byte string.
        message_data: The message data (either decompressed or raw).

    Returns:
        A 20-byte message ID.
    """
    # Encode the topic length as little-endian uint64
    topic_len_bytes = len(topic).to_bytes(8, "little")

    # Concatenate all components
    data_to_hash = domain + topic_len_bytes + topic + message_data

    # Compute SHA256 and take first 20 bytes
    digest = hashlib.sha256(data_to_hash).digest()
    return digest[:20]
