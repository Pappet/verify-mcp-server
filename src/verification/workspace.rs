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
