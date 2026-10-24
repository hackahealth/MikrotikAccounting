"""In-memory stand-in for a RouterOS API connection (librouteros-like), backed by an optional FTP root."""
import os


def ros_value(v):
    """What librouteros returns for a word: '1001' -> 1001, 'yes'/'true' -> True, 'no'/'false' -> False."""
    if not isinstance(v, str):
        return v
    try:
        i = int(v)
        if str(i) == v:
            return i
    except ValueError:
        pass
    return {"yes": True, "true": True, "no": False, "false": False}.get(v, v)


class FakePath:
    def __init__(self, router, key):
        self.router, self.key = router, key

    @property
    def items(self):
        return self.router.store.setdefault(self.key, [])

    def __iter__(self):
        if self.key == "file" and self.router.ftp_root:
            out = []
            for base, dirs, files in os.walk(self.router.ftp_root):
                rel = os.path.relpath(base, self.router.ftp_root).replace("\\", "/")
                for d in dirs:
                    out.append({"name": (d if rel == "." else f"{rel}/{d}"), "type": "directory"})
                for f in files:
                    out.append({"name": (f if rel == "." else f"{rel}/{f}"), "type": "file",
                                "size": os.path.getsize(os.path.join(base, f))})
            return iter(out)
        return iter([{k: ros_value(v) for k, v in i.items()} for i in self.items])

    def add(self, **kw):
        if kw.get("name") is not None and any(i.get("name") == kw.get("name") for i in self.items):
            raise RuntimeError("failure: already have such name")
        self.router.seq += 1
        item = {".id": f"*{self.router.seq:X}", "disabled": False}
        before = kw.pop("place-before", None)
        item.update(kw)
        pos = next((n for n, i in enumerate(self.items) if i[".id"] == before), None)
        if pos is None:
            self.items.append(item)
        else:
            self.items.insert(pos, item)
        return item[".id"]

    def update(self, **kw):
        item = next(i for i in self.items if i[".id"] == kw[".id"])
        item.update(kw)

    def remove(self, *ids):
        self.router.store[self.key] = [i for i in self.items if i[".id"] not in ids]


class FakeRouter:
    def __init__(self, ftp_root=None):
        self.store, self.seq, self.ftp_root = {}, 100, ftp_root
        self.calls = []

    def conn(self, nas=None):
        return FakeConn(self)


class FakeConn:
    def __init__(self, router):
        self.router = router

    def path(self, *parts):
        return FakePath(self.router, "/".join(parts))

    def __call__(self, cmd, **kw):
        self.router.calls.append((cmd, kw))
        parts = cmd.strip("/").split("/")
        key, action = "/".join(parts[:-1]), parts[-1]
        items = self.router.store.setdefault(key, [])
        for i in items:
            if i[".id"] == kw.get("numbers"):
                if action == "unset":
                    i.pop(kw["value-name"], None)
                elif action == "reset-counters":
                    i["bytes-in"] = i["bytes-out"] = 0
        return iter([])

    def close(self):
        pass
