"""
The `uuid` package generates UUID strings from socket cookies.

This package contains a single class, `UUID`, which generates UUID strings from
socket cookies. The UUID strings are in the format `<PREFIX>_<COOKIE>`, where
`PREFIX` is a user-defined prefix string read from a file and `COOKIE` is a
hexadecimal string representation of the socket cookie.

Usage:
    >>> import socket
    >>> uuid = UUID("uuid_prefix_tag.txt")
    >>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    >>> sock.connect(("localhost", 8080))
    >>> uuid_str = uuid.from_socket(sock)
    >>> print(uuid_str)
    my_prefix_1234ABCD

Classes:
    UUID: A class for generating UUID strings from socket cookies.
"""

import socket


# Static definition of _SO_COOKIE option code.
_SO_COOKIE = 57
_COOKIE_LENGTH = 8
__version__ = "1.0.0"


class UUID(object):
    """Generates UUIDs from socket cookies."""

    def __init__(self, prefix_file):
        """Creates a new UUID instance.

        Args:
          prefix_file (str): filename containing uuid prefix.

        Raises:
          FileNotFoundError: If prefix_file is not found.
        """
        with open(prefix_file) as p:
            self.prefix = p.read().strip()

    def from_socket(self, sock):
        """Generates a UUID string from the given socket cookie.

        Args:
          sock (socket.socket): open socket.

        Raises:
          ValueError: if the returned cookie is wrong length.
        """
        cookie = sock.getsockopt(socket.SOL_SOCKET, _SO_COOKIE, _COOKIE_LENGTH)
        if len(cookie) != _COOKIE_LENGTH:
            raise ValueError("incomplete cookie")
        hexcookie = cookie[::-1].hex().upper()
        return f"{self.prefix}_{hexcookie}"

import socket
if __name__ == "__main__":
    print('yes')
    # uuid = UUID("uuid_prefix_tag.txt")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(sock.getsockopt(socket.SOL_SOCKET, _SO_COOKIE, _COOKIE_LENGTH))
