import os
from typing import Dict, Any, List, Optional

class TarArchivePathTraversalSlipSanitizer:
    """
    Screens archive member paths prior to extraction to guarantee no paths escape
    the designated destination directory via `../`, symlinks, or absolute path prefixes.
    """
    def sanitize_archive_members(
        self,
        member_paths: List[str],
        destination_dir: str = "/tmp/sandbox/dest"
    ) -> Dict[str, Any]:
        dest_abs = os.path.abspath(destination_dir)
        safe_members = []
        blocked_members = []

        for member in member_paths:
            # Normalize and resolve relative path
            clean_member = member.lstrip("/").lstrip("\\")
            resolved_target = os.path.abspath(os.path.join(dest_abs, clean_member))

            # Common path traversal checks
            is_slip = (
                not resolved_target.startswith(dest_abs + os.sep) and
                resolved_target != dest_abs
            ) or (".." in member.split("/") or ".." in member.split("\\"))

            if is_slip:
                blocked_members.append({
                    "original_path": member,
                    "resolved_target": resolved_target,
                    "threat": "PATH_TRAVERSAL_ZIP_SLIP"
                })
            else:
                safe_members.append({
                    "original_path": member,
                    "safe_extraction_path": resolved_target
                })

        return {
            "destination_root": dest_abs,
            "total_members_analyzed": len(member_paths),
            "safe_members_count": len(safe_members),
            "threats_blocked_count": len(blocked_members),
            "is_archive_safe": len(blocked_members) == 0,
            "safe_members": safe_members,
            "blocked_members": blocked_members
        }
