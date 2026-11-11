"""Cached short symlinks must not require bytes beyond the target."""
from types import SimpleNamespace
import pytest
from volatility3.framework import exceptions
from volatility3.plugins.linux.pagecache import Files


class CachedLink:
    def __init__(self, data, readable_length):
        self.data = data
        self.readable_length = readable_length

    def is_readable(self):
        return True

    def dereference(self):
        return self

    def cast(self, name, max_length, encoding, errors):
        if max_length > self.readable_length:
            raise exceptions.InvalidAddressException('kernel', 0x2000)
        return self.data[:max_length].split(b'\0')[0].decode(encoding, errors)


def inode(data, readable_length):
    return SimpleNamespace(is_link=True, has_member=lambda n: n == 'i_link',
                           i_link=CachedLink(data, readable_length), i_size=len(data))


def test_target_near_unmapped_page():
    assert Files._follow_symlink(inode(b'../vcsa24', 16), '/dev/char/7:152') == '/dev/char/7:152 -> ../vcsa24'


def test_target_excludes_adjacent_allocation():
    obj=inode(b'target', 255)
    obj.i_link.data=b'targetUNRELATED'
    assert Files._follow_symlink(obj, '/link') == '/link -> target'


def test_existing_display_length_limit():
    assert Files._follow_symlink(inode(b'x'*400, 400), '/link') == '/link -> ' + 'x'*255


def test_zero_length_target():
    assert Files._follow_symlink(inode(b'', 0), '/link') == '/link'
