#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "shadowMemory.h"

#define PAGESIZE 0x80000
#define MAXNUM (PAGESIZE / sizeof(struct TreeNodeStruct))

unsigned int numOfTerminals = 0, numOfNodes = 0;
TreeNodePointer treeNodeTable[MAXNUM], heap = NULL, tree = NULL;

TreeNode noFreeMalloc() {
     if (heap == NULL || numOfNodes == MAXNUM) {
         heap = (TreeNodePointer) mmap(0, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
         numOfNodes = 0;
     }
     numOfNodes += 1;
     return heap + numOfNodes - 1;
}

void initTreeNodeTable() {
    int i;
    numOfTerminals = 0;
    for (i = 0; i < MAXNUM; i++) {
		treeNodeTable[i] = NULL;
	}
}

TreeNode initTreeNode() {
	TreeNode newNode = noFreeMalloc();
	// TreeNode newNode = (TreeNode) malloc(sizeof(struct TreeNodeStruct));
	newNode->taintLabel = 0;
	newNode->left = NULL;
	newNode->right = NULL;
	newNode->parent = NULL;

	return newNode;
}

void initBinaryTrie() {
    numOfNodes = 0;
    heap = NULL;
    tree = initTreeNode();
}

LABEL insertTrimmedBitVector(TreeNode root, char *bitVector, int bitVectorLength) {
	TreeNode node = NULL;

	if (bitVectorLength == 0) {
		if (root->taintLabel == 0) {
			// root has not be inserted
			root->taintLabel = numOfTerminals + 1;
			treeNodeTable[root->taintLabel] = root;
			numOfTerminals++;
		}
		return root->taintLabel;
	}

	if (bitVector[0] == '0') {
		node = root->left;
	} else {
		node = root->right;
	}

	if (!node) {
		node = initTreeNode();
		node->parent = root;
		if (bitVector[0] == '0') {
            root->left = node;
        } else {
            root->right = node;
        }
		if (bitVectorLength == 1) {
			node->taintLabel = numOfTerminals + 1;
			treeNodeTable[node->taintLabel] = node; // push the new node into tree node table
			numOfTerminals++;
		}
	}

	if (bitVectorLength == 1) {
        if (node->taintLabel == 0) {
            node->taintLabel = numOfTerminals + 1;
            treeNodeTable[node->taintLabel] = node; // push the existing node into tree node table
			numOfTerminals++;
        }
		return node->taintLabel;
	} else {
		// iteratively insert the bit vector where the subBitVector(bitVector[1..]) is vector after first element removed
		return insertTrimmedBitVector(node, bitVector + 1, bitVectorLength - 1);
	}
}

// Inserts a binary tree represented by the bit vector.
// Returns a label representing the binary tree.
// Always return the same label for identical binary trees.
LABEL insertBitVector(TreeNode root, char *bitVector) {
	int i;
	int last = strlen(bitVector);

	// Trims the trailing '0' elements in bitVector
    for (i = last - 1; i >= 0; i--) {
        if (bitVector[i] == '1') {
            break;
        }
    }
    last = i + 1;

    // Checks if the trimmed bit vector already exists or inserts if not exists
    return insertTrimmedBitVector(root, bitVector, last);
}

char *findBitVector(LABEL index) {
	int len = 0;
	char *vector = NULL;
	TreeNode node, parent;
	
	node = treeNodeTable[index];
	parent = node->parent;
	while (parent) {
        len++;
        node = parent;
		parent = node->parent;
	}

	vector = (char *) malloc(sizeof(char) * (len + 1));
	vector[len] = '\0';
	len--;
	node = treeNodeTable[index];
	parent = node->parent;
	while (len >= 0) {
		if (node == parent->left) {
			vector[len] = '0';
		} else {
			vector[len] = '1';
		}
        node = parent;
		parent = node->parent;
        len--;
	}

	return vector;
}

LABEL unionBitVectors(TreeNode root, LABEL t1, LABEL t2) {
	char *v = NULL;
	char *v1 = findBitVector(t1);
	char *v2 = findBitVector(t2);
	int i, len1 = strlen(v1), len2 = strlen(v2);
	LABEL result;

	if (len1 < len2) {
		v = (char *) malloc(sizeof(char) * (len2 + 1));
		v[len2] = '\0';
		for (i = 0; i < len1; i++) {
            if (v1[i] == '0' && v2[i] == '0') {
                v[i] = '0';
            } else {
                v[i] = '1';
            }
		}
		for (i = len1; i < len2; i++) {
			v[i] = v2[i];
		}
	} else {
		v = (char *) malloc(sizeof(char) * (len1 + 1));
		v[len1] = '\0';
		for (i = 0; i < len2; i++) {
			if (v1[i] == '0' && v2[i] == '0') {
                v[i] = '0';
            } else {
                v[i] = '1';
            }
		}
		for (i = len2; i < len1; i++) {
			v[i] = v1[i];
		}
	}

	result = insertBitVector(root, v);
	free(v1);
	free(v2);
	free(v);
	return result;
}

/* 
int main() {
    initBinaryTrie();
	initTreeNodeTable();

	insertBitVector(tree, bitVector);
	findBitVector(label)
	unionBitVectors(tree, label_1, label_2);

	return 0;
}
 */
 