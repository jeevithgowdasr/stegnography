"""Domain-specific exceptions for Image Encryption and Steganography."""


class StegoError(Exception):
    """Base exception for all steganography and encryption errors."""
    pass


class ImageCapacityExceededError(StegoError):
    """Raised when the payload size exceeds the cover image's embedding capacity."""
    def __init__(self, required_bytes: int, available_bytes: int):
        self.required_bytes = required_bytes
        self.available_bytes = available_bytes
        super().__init__(
            f"Payload requires {required_bytes:,} bytes, but the cover image only supports {available_bytes:,} bytes."
        )


class DecryptionError(StegoError):
    """Raised when authentication tag fails or password is incorrect."""
    pass


class CorruptedPayloadError(StegoError):
    """Raised when the steganographic payload is missing magic bytes or malformed."""
    pass


class UnsupportedFormatError(StegoError):
    """Raised when an unsupported or lossy image format is provided."""
    pass


class ImageValidationError(StegoError):
    """Raised when an image file cannot be loaded or has invalid dimensions."""
    pass
