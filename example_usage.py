import json
from client import TarArchivePathTraversalSlipSanitizer

def main():
    sanitizer = TarArchivePathTraversalSlipSanitizer()
    archive_paths = [
        "src/main.py",
        "README.md",
        "../../../../etc/passwd",
        "subfolder/util.py",
        "../../../root/.ssh/authorized_keys"
    ]
    result = sanitizer.sanitize_archive_members(archive_paths, destination_dir="/app/sandbox")
    print("Archive Path Sanitization:")
    print(json.dumps(result, indent=2))
    assert result["is_archive_safe"] is False
    assert result["threats_blocked_count"] == 2
    assert len(result["safe_members"]) == 3
    print("Archive sanitizer verification complete: PASS")

if __name__ == "__main__":
    main()
