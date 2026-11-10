"""Physical socket candidates must survive invalid hits and deduplicate by address."""

from types import SimpleNamespace

from volatility3.framework.symbols import linux
from volatility3.plugins.linux import sockscan, sockstat


def test_unresolved_socket_container_is_rejected(monkeypatch):
    module = SimpleNamespace(symbol_table_name="vmlinux", layer_name="kernel")
    file = SimpleNamespace(get_dentry=lambda: SimpleNamespace(d_inode=0x1234))
    plugin = SimpleNamespace(
        context=SimpleNamespace(
            modules={"kernel": module}, object=lambda *args, **kwargs: file
        )
    )
    monkeypatch.setattr(linux.LinuxUtilities, "container_of", lambda *args: None)
    assert (
        sockscan.Sockscan._walk_file_ops_needles(
            plugin, "kernel", "memory", 0x2000, 0x40
        )
        is None
    )


def scan_fixture(monkeypatch, hits, walk, extract):
    module = SimpleNamespace(
        symbol_table_name="vmlinux",
        layer_name="kernel",
        object_from_symbol=lambda **kwargs: object(),
    )
    memory = SimpleNamespace(scan=lambda *args: iter(hits))
    context = SimpleNamespace(
        modules={"kernel": module},
        layers={"memory": memory},
        object=lambda *args, **kwargs: SimpleNamespace(
            vol=SimpleNamespace(offset=kwargs["offset"])
        ),
    )
    monkeypatch.setattr(sockstat, "SockHandlers", lambda *args: object())
    return SimpleNamespace(
        context=context,
        _progress_callback=None,
        _find_memory_layer_name=lambda *args: "memory",
        _find_file_ops_needles=lambda *args: ({b"file"}, 0x10),
        _find_sk_destruct_needles=lambda *args: ({b"destructor"}, 4),
        _walk_file_ops_needles=walk,
        _extract_sock_fields=extract,
    )


def test_file_hits_do_not_share_none_key_and_cross_method_duplicates_are_removed(
    monkeypatch,
):
    plugin = scan_fixture(
        monkeypatch,
        [
            (0x10, b"file"),
            (0x20, b"file"),
            (0x104, b"destructor"),
            (0x204, b"destructor"),
        ],
        lambda module, memory, hit, offset: SimpleNamespace(
            vol=SimpleNamespace(offset={0x10: 0x100, 0x20: 0x200}[hit])
        ),
        lambda sock, handler: (sock.vol.offset,),
    )
    assert list(sockscan.Sockscan._generator(plugin, "kernel")) == [
        (0, (0x100,)),
        (0, (0x200,)),
    ]


def test_rejected_candidate_does_not_hide_a_later_valid_hit(monkeypatch):
    fields = iter([None, (0x100,)])
    plugin = scan_fixture(
        monkeypatch,
        [(0x104, b"destructor"), (0x104, b"destructor")],
        lambda *args: None,
        lambda *args: next(fields),
    )
    assert list(sockscan.Sockscan._generator(plugin, "kernel")) == [(0, (0x100,))]
