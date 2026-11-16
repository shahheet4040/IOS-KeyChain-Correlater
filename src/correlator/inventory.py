from pathlib import Path
import plistlib
from typing import Any, Dict


def scan_containers(root: str | Path) -> Dict[str, Dict[str, str]]:
    """
    Looks under private/var/mobile/Containers/Data/Application/* (kind app_data)
    and private/var/mobile/Containers/Shared/AppGroup/* (kind app_group).
    If private/var/mobile is missing, tries var/mobile instead.
    If neither location exists, raises ValueError saying root does not look like an iOS filesystem.
    Reads .com.apple.mobile_container_manager.metadata.plist in each container with plistlib
    and takes the MCMMetadataIdentifier value as bundle_id.
    Missing plist or key: bundle_id is 'unknown'.
    Returns a map from container folder name to {'kind': kind, 'bundle_id': bundle_id}.
    """
    root_path = Path(root).resolve()

    mobile_dir = None
    for cand in [root_path / "private" / "var" / "mobile", root_path / "var" / "mobile"]:
        if cand.is_dir():
            mobile_dir = cand
            break

    if mobile_dir is None:
        raise ValueError(f"Root does not look like an iOS filesystem: missing var/mobile in {root_path}")

    containers_map: Dict[str, Dict[str, str]] = {}

    targets = [
        (mobile_dir / "Containers" / "Data" / "Application", "app_data"),
        (mobile_dir / "Containers" / "Shared" / "AppGroup", "app_group"),
    ]

    for base_dir, kind in targets:
        if not base_dir.is_dir():
            continue

        for container_dir in sorted(base_dir.iterdir()):
            if not container_dir.is_dir():
                continue

            folder_name = container_dir.name
            bundle_id = "unknown"

            plist_path = container_dir / ".com.apple.mobile_container_manager.metadata.plist"
            if plist_path.is_file():
                try:
                    with open(plist_path, "rb") as f:
                        meta = plistlib.load(f)
                    if isinstance(meta, dict):
                        bundle_id = str(meta.get("MCMMetadataIdentifier") or "unknown")
                except Exception:
                    bundle_id = "unknown"

            containers_map[folder_name] = {
                "kind": kind,
                "bundle_id": bundle_id,
            }

    return containers_map
