from common import bytes_to_int
from elliptic_curve import Point
from standard_curves import StandardCurve, get_curve, list_curves

"""
https://andrea.corbellini.name/2023/01/02/ec-encryption/
"""


def message_to_point(message: bytes, curve: StandardCurve) -> Point:
    # Number of bytes to represent a coordinate of a point
    coordinate_size = curve.p.bit_length() // 8
    # Minimum number of bytes for the padding. We need at least 1 byte so that
    # we can try different values and find a valid point. We also add an extra
    # byte as a delimiter between the message and the padding (see below)
    min_padding_size = 2
    # Maximum number of bytes that we can encode
    max_message_size = coordinate_size - min_padding_size

    if len(message) > max_message_size:
        raise ValueError("Message too long")

    # Add a padding long enough to ensure that the resulting padded message has
    # the same size as a point coordinate. Initially the padding is all 0
    padding_size = coordinate_size - len(message)
    padded_message = bytearray(message) + b"\0" * padding_size

    # Put a delimiter between the message and the padding, so that we can
    # properly remove the padding at decrypt time
    padded_message[len(message)] = 0xFF

    while True:
        # Convert the padded message to an integer, which may or may not be a
        # valid x-coordinate
        x = bytes_to_int(padded_message)
        # Calculate the corresponding y-coordinate (if it exists)
        y = curve.curve.y_recover(x)
        if y is None:
            # x was not a valid coordinate; increment the padding and try again
            padded_message[-1] += 1
        else:
            # x was a valid coordinate; return the point (x, y)
            return y


def point_to_message(point: Point, curve: StandardCurve) -> bytes:
    # Number of bytes to represent a coordinate of a point
    coordinate_size = curve.p.bit_length() // 8
    # Convert the x-coordinate of the point to a byte string
    padded_message = point.x.to_bytes(coordinate_size, "little")
    # Find the padding delimiter
    message_size = padded_message.rfind(0xFF)
    # Remove the padding and return the resulting message
    message = padded_message[:message_size]
    return message


if __name__ == "__main__":
    message = b"Hello, world ni haoa "

    for curve in list_curves():
        print(f"message: {message}; curve:{curve}")
        p = message_to_point(message, curve)
        print(f"point: {p}")
        m1 = point_to_message(p, curve)
        print(f"m1: {m1}")
