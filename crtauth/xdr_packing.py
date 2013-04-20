from crtauth import packing

import xdrlib


class Packer(xdrlib.Packer, packing.Packer):
    pass


class Unpacker(xdrlib.Unpacker, packing.Unpacker):
    pass
