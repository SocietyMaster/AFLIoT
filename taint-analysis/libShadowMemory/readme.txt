全局变量定义
- TreeNodePointer treeNodeTable[MAXNUM];
- TreeNodePointer tree;

API调用

LABEL insertBitVector(tree, char *bitVector);
  - input: 全局变量tree, 字符(01)串bitVector
  - output: bitVector的label（即bitVector在treeNodeTable中的index）
  - 将一个bitVector插入binary trie，并更新tree node table，两个相同的bitVector对应的label相同。

char *findBitVector(LABEL label);
  - input: 某个bitVector的label
  - output: label对应的bitVector
  - 给定一个label，在tree node table中找到label对应的bitVector最后一个字符的指针，从该指针指向的节点开始回溯binary trie，直到根节点，则获取到bitVector整个01串。

LABEL unionBitVectors(tree, LABEL label_1, LABEL label_2);
  - input: 全局变量tree，bitVector_1对应的label_1，bitVector_2对应的label_2
  - output: bitVector_1和bitVector_2执行union操作后得到的unionBitVector所对应的label
 