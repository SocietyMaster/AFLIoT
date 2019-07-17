typedef unsigned int LABEL;
typedef struct TreeNodeStruct *TreeNode, *TreeNodePointer;

struct TreeNodeStruct {
	LABEL taintLabel;
	TreeNodePointer left;
	TreeNodePointer right;
	TreeNodePointer parent;
};

TreeNode noFreeMalloc();
void initTreeNodeTable();
TreeNode initTreeNode();
void initBinaryTrie();
LABEL insertTrimmedBitVector(TreeNode, char *, int);
LABEL insertBitVector(TreeNode, char *);
char *findBitVector(LABEL);
LABEL unionBitVectors(TreeNode, LABEL, LABEL);
