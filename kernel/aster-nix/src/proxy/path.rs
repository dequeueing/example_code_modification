use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

bitflags! {
    pub struct Permission: u32 {
        const F_OK = 0;
        const R_OK = 1 << 2;
        const W_OK = 1 << 1;
        const X_OK = 1 << 0;
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum HostFileType {
    File,
    Dir,
    Socket,
    AlreadyUsed,
}

pub struct PathNode {
    pub is_end_of_path: bool,
    pub perm: Permission,     // file mode: rwx
    pub hostft: HostFileType, // file type: file, dir
    pub size: Option<usize>,  // file size, if dir, size is None
    pub children: BTreeMap<String, PathNode>,
}

impl PathNode {
    pub const fn new_root() -> Self {
        PathNode {
            is_end_of_path: false,
            perm: Permission::all(),
            hostft: HostFileType::Dir,
            size: None,
            children: BTreeMap::new(),
        }
    }
    pub fn new(p: Permission, file_size: Option<usize>, hostft: HostFileType) -> Self {
        PathNode {
            is_end_of_path: false,
            perm: p,
            hostft: hostft,
            size: file_size,
            children: BTreeMap::new(),
        }
    }
}

pub struct PathTree {
    root: PathNode,
}

impl PathTree {
    pub const fn new() -> Self {
        PathTree {
            root: PathNode::new_root(),
        }
    }

    pub fn get_file_size(&mut self, path: &str) -> Option<usize> {
        let node = self.get_parent_node(path);
        match node {
            None => {
                return None;
            }
            Some(node) => {
                return node.size;
            }
        }
    }

    pub fn get_file_perm(&mut self, path: &str) -> Option<Permission> {
        let node = self.get_parent_node(path);
        match node {
            None => {
                return None;
            }
            Some(node) => {
                return Some(node.perm);
            }
        }
    }

    pub fn set_file_size(&mut self, path: &str, size: usize) {
        let node = self.get_parent_node(path);
        match node {
            None => {
                return;
            }
            Some(node) => {
                node.size = Some(size);
            }
        }
    }

    pub fn get_parent_node(&mut self, path: &str) -> Option<&mut PathNode> {
        let parts: Vec<&str> = path.split('/').collect();
        let parts = &parts[..parts.len() - 1]; // Ignore the last part of the path

        let mut node = &mut self.root;

        for part in parts {
            match node.children.get_mut(*part) {
                Some(child) => node = child,
                None => return None,
            }
        }
        Some(node)
    }

    pub fn get_children(&self, path: &str) -> Option<Vec<String>> {
        let parts: Vec<&str> = path.split('/').collect();
        let mut node = &self.root;

        for part in parts {
            match node.children.get(part) {
                Some(child) => node = child,
                None => return None,
            }
        }

        Some(node.children.keys().cloned().collect())
    }

    pub fn insert(&mut self, path: &str, perm: Permission) {
        let mut node = &mut self.root;
        let parts: Vec<&str> = path.split('/').collect();

        for part in parts {
            node = node
                .children
                .entry(part.to_string())
                .or_insert(PathNode::new(perm, Some(0), HostFileType::File));
        }

        node.is_end_of_path = true;
    }

    pub fn insert_dir(&mut self, path: &str, perm: Permission) {
        let mut node = &mut self.root;
        let parts: Vec<&str> = path.split('/').collect();

        for part in parts {
            node = node
                .children
                .entry(part.to_string())
                .or_insert(PathNode::new(perm, None, HostFileType::Dir));
        }
    }

    pub fn search(&self, path: &str) -> bool {
        let mut node = &self.root;
        let parts: Vec<&str> = path.split('/').collect();

        for part in parts {
            match node.children.get(part) {
                Some(next_node) => node = next_node,
                None => return false,
            }
        }
        node.is_end_of_path
    }

    pub fn search_dir(&self, path: &str) -> bool {
        let mut node = &self.root;
        let parts: Vec<&str> = path.split('/').collect();

        for part in parts {
            match node.children.get(part) {
                Some(next_node) => node = next_node,
                None => return false,
            }
        }
        node.hostft == HostFileType::Dir
    }

    pub fn rename(&mut self, old_path: &str, new_path: &str) {
        let perm = self.get_parent_node(old_path).unwrap().perm;
        remove(old_path, self);
        self.insert(new_path, perm);
    }
}

pub fn remove(path: &str, pt: &mut PathTree) {
    let parts: Vec<&str> = path.split('/').collect();
    remove_recursive(&mut pt.root, &parts, 0);
}

fn remove_recursive(node: &mut PathNode, parts: &[&str], index: usize) -> bool {
    if index == parts.len() {
        if node.is_end_of_path {
            node.is_end_of_path = false;
            return node.children.is_empty();
        }
        return false;
    }

    if let Some(child) = node.children.get_mut(parts[index]) {
        if remove_recursive(child, parts, index + 1) {
            if child.children.is_empty() && !child.is_end_of_path {
                node.children.remove(parts[index]);
            }
            return node.is_end_of_path && node.children.is_empty();
        }
    }
    false
}

// convert dirfd and pathname to direct path
pub fn convert_dirfd_to_path(dirfd: usize, pathname: &str) -> String {
    let mut path = String::new();
    if dirfd as isize == -100 {
        path.push_str(pathname);
    } else {
        // FIXME!!
        // now only support dirfd = -100
        todo!()
    }
    path
}
