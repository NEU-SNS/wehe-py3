import os
import socket
import tempfile
import unittest
import uuid
from unittest import mock


class TestUUID_from_socket(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as tempdir:
            # Write uuid prefix to temp file.
            tmpname = os.path.join(tempdir, 'prefix.file')
            with open(tmpname, 'w') as temp:
                temp.write("ndt-kps5n_1619746702\n")
            # Initialize UUID instance.
            self.uuid = uuid.UUID(tmpname)

    def test_from_socket(self):
        mock_sock = mock.MagicMock(spec=socket.socket)
        mock_sock.getsockopt.return_value = b'\xd1\rr\x00\x00\x00\x00\x00'

        s = self.uuid.from_socket(mock_sock)

        self.assertEqual('ndt-kps5n_1619746702_0000000000720DD1', s)

if __name__ == '__main__':
    unittest.main()
