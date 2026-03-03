use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

/// Compute a hash of the workspace directory, respecting .gitignore.
pub fn compute_workspace_hash(working_dir: &str) -> String {
    let mut hasher = Sha256::new();
    let mut files_hashed = 0;

    let walker = WalkBuilder::new(working_dir)
        .hidden(true)
        .git_ignore(true)
        .git_exclude(true)
        .build();

    let mut paths: Vec<_> = walker.filter_map(Result::ok).collect();
    // Sort paths to ensure deterministic hashing order
    paths.sort_by(|a, b| a.path().cmp(b.path()));

    for entry in paths {
        let path = entry.path();
        if path.is_file() {
            if let Ok(mut file) = fs::File::open(path) {
                // Hash the relative path so renames affect the hash
                if let Ok(rel_path) = path.strip_prefix(working_dir) {
                    hasher.update(rel_path.to_string_lossy().as_bytes());
                }

                let mut buffer = [0; 8192];
                while let Ok(count) = file.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    hasher.update(&buffer[..count]);
                }
                files_hashed += 1;
            }
        }
    }

    let result = hasher.finalize();
    format!("{:x}_{}", result, files_hashed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;
    use std::process::Command;

    // Helper to create a temp dir with a unique name
    fn create_temp_dir(name: &str) -> std::path::PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("verify_mcp_workspace_test_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn test_workspace_hash_deterministic() {
        let dir = create_temp_dir("deterministic");
        File::create(dir.join("file1.txt")).unwrap().write_all(b"hello").unwrap();
        File::create(dir.join("file2.txt")).unwrap().write_all(b"world").unwrap();

        let hash1 = compute_workspace_hash(dir.to_str().unwrap());
        let hash2 = compute_workspace_hash(dir.to_str().unwrap());

        assert_eq!(hash1, hash2, "Hashing the same directory twice should yield the same result");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_workspace_hash_changes_on_content_change() {
        let dir = create_temp_dir("content_change");
        let file_path = dir.join("file.txt");
        File::create(&file_path).unwrap().write_all(b"version1").unwrap();

        let hash1 = compute_workspace_hash(dir.to_str().unwrap());

        File::create(&file_path).unwrap().write_all(b"version2").unwrap();
        let hash2 = compute_workspace_hash(dir.to_str().unwrap());

        assert_ne!(hash1, hash2, "Hash should change when file content changes");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_workspace_hash_changes_on_rename() {
        let dir = create_temp_dir("rename");
        let file1_path = dir.join("file1.txt");
        let file2_path = dir.join("file2.txt");
        File::create(&file1_path).unwrap().write_all(b"content").unwrap();

        let hash1 = compute_workspace_hash(dir.to_str().unwrap());

        fs::rename(&file1_path, &file2_path).unwrap();
        let hash2 = compute_workspace_hash(dir.to_str().unwrap());

        assert_ne!(hash1, hash2, "Hash should change when a file is renamed");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_workspace_hash_ignores_gitignored_files() {
        let dir = create_temp_dir("gitignore");

        // git init inside the temp directory
        let status = Command::new("git")
            .arg("init")
            .current_dir(&dir)
            .status()
            .expect("Failed to initialize git repository");
        assert!(status.success(), "git init failed");

        // Create a tracked file
        File::create(dir.join("tracked.txt")).unwrap().write_all(b"tracked").unwrap();
        // Create .gitignore
        File::create(dir.join(".gitignore")).unwrap().write_all(b"ignored.txt\n").unwrap();

        let hash1 = compute_workspace_hash(dir.to_str().unwrap());

        // Create ignored file
        File::create(dir.join("ignored.txt")).unwrap().write_all(b"ignored").unwrap();
        let hash2 = compute_workspace_hash(dir.to_str().unwrap());

        assert_eq!(hash1, hash2, "Hash should be the same even if an ignored file is added");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_workspace_hash_empty_dir() {
        let dir = create_temp_dir("empty");
        let hash = compute_workspace_hash(dir.to_str().unwrap());
        
        // It should return a valid hash for an empty directory.
        assert!(hash.ends_with("_0"), "Hash of empty directory should end with _0");
        let _ = fs::remove_dir_all(dir);
    }
}
