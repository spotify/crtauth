class Packer(object):
    def pack_fstring(n, s):
        """
        Pack the specified fixed length string into the buffer associated with
        this packer.

        :param n: length of the fixed length string
        :param s: string to pack, must be of the length n
        """
        raise NotImplementedError("pack_fstring")

    def pack_string(s):
        """
        Pack the specified string into the buffer associated with this packer.

        :param i: string to pack
        """
        raise NotImplementedError("pack_string")

    def pack_uint(i):
        """
        Pack the specified unsigned integer into the buffer associated with
        this packer.

        :param i: integer to pack
        """
        raise NotImplementedError("pack_uint")

    def get_buffer(self):
        raise NotImplementedError("get_buffer")


class Unpacker(object):
    def unpack_fstring(n):
        """
        Unpack the specified fixed length string into the buffer associated
        with this unpacker.

        :param n: length of the fixed length string
        """
        raise NotImplementedError("unpack_fstring")

    def unpack_string():
        """
        Unpack the specified string from the buffer associated with this
        unpacker.
        """
        raise NotImplementedError("unpack_string")

    def unpack_uint():
        """
        Unpack the specified unsigned integer from the buffer associated with
        this unpacker.
        """
        raise NotImplementedError("unpack_uint")
