"""Independent verifying readers: checkpoint polls plus only new/changed tiles."""

from aics_tlog import MerkleTree, leaf_hash
from aics_tlog.tiles import entry_bundle_path, parse_entry_bundle, tile_path

from ..client import require


async def tile_checkpoint_reads(client):
    client.runner.measure()

    async def worker(number):
        entries = []
        cache = {}
        previous_root = None
        while True:
            head = await client.checkpoint(agent=f"reader-{number}")
            require(head.size >= len(entries), "checkpoint_rollback")
            if head.size == len(entries) and previous_root is not None:
                require(head.root == previous_root, "checkpoint_equivocation")
            for bundle in range(len(entries) // 256, (head.size + 255) // 256):
                width = min(256, head.size - bundle * 256)
                width_arg = None if width == 256 else width
                paths = (tile_path(0, bundle, width_arg), entry_bundle_path(bundle, width_arg))
                resources = []
                for kind, path in enumerate(paths):
                    if path not in cache:
                        cache[path] = await client.get(
                            "/" + path,
                            operation="tile",
                            tiles=True,
                            raw=True,
                            agent=f"reader-{number}",
                            missing_ok=width < 256,
                        )
                    if cache[path] is None:
                        # C2SP permits pruning a partial once its full tile exists.
                        full = tile_path(0, bundle, None) if kind == 0 else entry_bundle_path(bundle, None)
                        if full not in cache:
                            cache[full] = await client.get(
                                "/" + full, operation="tile", tiles=True, raw=True, agent=f"reader-{number}"
                            )
                        cache[path] = cache[full]
                    resources.append(cache[path])
                hashes, raw = resources
                leaves = parse_entry_bundle(raw)[:width]
                hashes = hashes[: width * 32]
                require(
                    len(leaves) == width and hashes == b"".join(leaf_hash(x) for x in leaves),
                    "tile_entry_mismatch",
                )
                start = bundle * 256
                overlap = max(0, len(entries) - start)
                require(entries[start:] == leaves[:overlap], "tile_history_changed")
                entries.extend(leaves[overlap:])
            require(MerkleTree(entries).root() == head.root, "tile_root_mismatch")
            previous_root = head.root
            await client.runner.sleep(client.runner.config.think_time)

    await client.runner.workers(worker(i) for i in range(client.runner.config.agents))
