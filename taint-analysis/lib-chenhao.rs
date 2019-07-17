//! Implements a data structure for sets.
//!
//! A set `S={s_i}` where `s_i` is `usize`.
//! Supports two operations:
//! * `insert(s)`: Inserts a set `s` represented by a bit vector.
//! Returns a unique integer label representing the set.
//! * `union(i, j)`: Computes the union of the sets whose labels are `i` and `j`.
//! Returns the label of the new set.

struct Node<T> {
    label: T,
    left: Link<T>,
    right: Link<T>,
    parent: Option<*const Node<T>>,
}

type Link<T> = Option<Box<Node<T>>>;

impl<T> Node<T> {
    fn new(label: T, parent: Option<*const Node<T>>) -> Self {
        Node {
            label: label,
            left: None,
            right: None,
            parent: parent,
        }
    }
}

// If the node represents a set, it is a terminal node and has `Node<Some<_>>`.
// Otherwise, it is a non-terminal node and has `Node<None>`.
type TreeNode = Node<Option<usize>>;

pub struct Sets {
    // Root of the tree
    root: Link<Option<usize>>,
    // Points to the terminals of the tree where each terminal represents a set.
    // The indices in `terminals` are the labels of the corresponding terminals.
    terminals: Vec<*const TreeNode>,
}

enum NewNode {
    Label(usize),
    Node(*const TreeNode),
}

impl Sets {
    pub fn new() -> Self {
        Sets {
            // The root node has no parent, and initially is a non-terminal.
            root: Some(Box::new(Node::new(None, None))),
            terminals: Vec::new(),
        }
    }

    /// Inserts a set represented by the bit vector `v`.
    /// Returens a label representing the set.
    /// Always return the same label for identical sets.
    pub fn insert(&mut self, mut v: &[bool]) -> usize {
        // Trims the trailing `false` elements in `v`
        let mut last = v.len();
        for (i, &x) in v.iter().rev().enumerate() {
            if x {
                last = i;
                break;
            }
        }
        v = &v[0..(v.len() - last)];
        // Checks if `v` contains no `true`
        match Sets::insert_(self.root.as_mut().unwrap(), v, self.terminals.len()) {
            // The set already exists, so returns the existing label.
            NewNode::Label(label) => label,
            // This set is new, so assigns a new label.
            NewNode::Node(node) => {
                let len = self.terminals.len();
                self.terminals.push(node);
                len
            }
        }
    }

    /// Computes the union of two sets.
    /// Input: the labels representing the two sets.
    /// Returns:
    /// * `Some(label)`: the label of the new set.
    /// * `None`: one of the input labels does not exist.
    pub fn union(&mut self, label1: usize, label2: usize) -> Option<usize> {
        let mut v1 = match self.find(label1) {
            Some(x) => x,
            None => return None,
        };
        let mut v2 = match self.find(label2) {
            Some(x) => x,
            None => return None,
        };
        if v1.len() < v2.len() {
            std::mem::swap(&mut v1, &mut v2);
        }
        let mut v = Vec::with_capacity(v1.len());
        for (&x, &y) in v1.iter().zip(v2.iter()) {
            v.push(x || y);
        }
        for &i in &v1[v2.len()..] {
            v.push(i);
        }
        Some(self.insert(&v))
    }

    /// Starting at a terminal, finds the bit vector representing the set
    /// by walking up the tree.
    /// Input: the label representing the set.
    /// Returns:
    /// * `Some(_)`: the bit vector representing the set.
    /// * `None`: the label doesn't exist.
    fn find(&self, label: usize) -> Option<Vec<bool>> {
        if label >= self.terminals.len() {
            return None;
        }
        let mut v = vec!();
        let mut node = unsafe { &*self.terminals[label] };
        while let Some(parent) = node.parent {
            let parent = unsafe { &*parent };
            let mut found = false;
            if let Some(ref left) = parent.left {
                // Is `node` the left child of `parent`?
                if left as &TreeNode as *const TreeNode == node as *const TreeNode {
                    found = true;
                    v.push(false);
                }
            }
            if !found {
                if let Some(ref right) = parent.right {
                    // Is `node` the right child of `parent`?
                    if right as &TreeNode as *const TreeNode == node as *const TreeNode {
                        found = true;
                        v.push(true);
                    }
                }
                if !found {
                    panic!("Node is neither the left or right child of parent.");
                }
            }
            node = parent;
        }
        v.reverse();
        Some(v)
    }

    /// Inserts a bit vector representing a set.
    /// Input:
    /// * `root`: the root of the tree.
    /// * `v`: the bit vector.
    /// * `label`: if this set is new, use this new label for the new set.
    /// Output:
    /// * NewNode::Label(label): this set already exists with label `label`.
    /// * NewNode::Node(node): this set is new. `node` is its terminal.
    fn insert_(root: &mut TreeNode, v: &[bool], label: usize) -> NewNode {
        // If `v` contains no `true`, then its terminal is the root.
        if v.is_empty() {
            return match root.label {
                // root has been inserted.
                Some(label_) => NewNode::Label(label_),
                // root has not be inserted.
                None => {
                    root.label = Some(label);
                    NewNode::Node(root)
                }
            };
        }

        // Traverses the next node. Creates it when necessary.
        let next;
        let is_new;
        // Gets a raw pointer before mutable borrowing root to appease borrowck
        let root_ptr = root as *const _;
        let (v0, v_rest) = v.split_first().unwrap();
        // Which branch to go next
        let child = if *v0 { &mut root.right } else { &mut root.left };
        match *child {
            Some(ref mut node) => {
                next = node;
                is_new = false;
            }
            None => {
                let label_ = match v_rest.len() {
                    // This is a terminal node.
                    0 => Some(label),
                    // This is a non-terminal node.
                    _ => None,
                };
                *child = Some(Box::new(Node::new(label_, Some(root_ptr))));
                next = child.as_mut().unwrap();
                is_new = true;
            }
        };

        match v_rest.len() {
            0 => match is_new {
                true => NewNode::Node(next as &TreeNode),
                false => match next.label {
                    // `next` is a terminal already.
                    Some(label) => NewNode::Label(label),
                    // `next` wasn't a termnial. Change it to a terminal.
                    None => {
                        next.label = Some(label);
                        NewNode::Node(next as &TreeNode)
                    }
                },
            },
            _ => Sets::insert_(next, v_rest, label),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let mut tree = Sets::new();
        let insert: &[&[_]] = &[&[false],
                                &[false],
                                &[false, true],
                                &[true, false],
                                &[false, true],
                                &[true, true],
                                &[false, false, false, true]];
        let union: &[(&[_], &[_])] = &[(&[false], &[false, true]),
                                       (&[false], &[true, true]),
                                       (&[true, false], &[false, true]),
                                       (&[false, false, false, true], &[true, false])];

        println!("Insert:");
        for &i in insert {
            println!("{}", tree.insert(i));
        }
        println!("Union:");
        for &(i, j) in union {
            let l1 = tree.insert(i);
            let l2 = tree.insert(j);
            println!("{}", tree.union(l1, l2).unwrap());
        }
    }
}
