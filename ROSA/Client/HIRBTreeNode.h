#ifndef HIRBTREENODE_H
#define HIRBTREENODE_H

#include <string>
#include <list>

class HIRBTreeNode
{
public:
    HIRBTreeNode() = default;
    HIRBTreeNode(bool if_leaf);
    ~HIRBTreeNode() = default;
    void to_string(std::string &str_out);
    void from_string(const std::string &str_in);
    void split(HIRBTreeNode &sibling_out, const std::string &wedge);
    std::string meage(const HIRBTreeNode &sibling_in);
    void clear();

    bool if_leaf = false;
    std::list<std::string> lhash, values, children;
};

#endif