#include "HIRBTreeNode.h"
#include <iostream>
extern "C"
{
#include <string.h>
}
using namespace std;

HIRBTreeNode::HIRBTreeNode(bool if_leaf)
{
    this->if_leaf = if_leaf;
}

void HIRBTreeNode::to_string(string &str_out)
{
    int len;
    string tmp_str;
    char _if_leaf;

    str_out.clear();
    str_out.reserve(1024);

    len = lhash.size();

    tmp_str.assign((char *)&len, sizeof(int));
    str_out = tmp_str;
    for (auto &itr : lhash)
    {
        len = itr.size();
        tmp_str.assign((char *)&len, sizeof(int));
        str_out += tmp_str;
        str_out += itr;
    }

    len = values.size();

    tmp_str.assign((char *)&len, sizeof(int));
    str_out += tmp_str;
    for (auto &itr : values)
    {
        len = itr.size();
        tmp_str.assign((char *)&len, sizeof(int));
        str_out += tmp_str;
        str_out += itr;
    }

    if(if_leaf)
        _if_leaf = 1;
    else
        _if_leaf = 0;

    tmp_str.assign(&_if_leaf, sizeof(_if_leaf));
    str_out += tmp_str;
    if(if_leaf)
        return;
    len = children.size();

    tmp_str.assign((char *)&len, sizeof(int));
    str_out += tmp_str;
    for (auto &itr : children)
    {
        len = itr.size();
        tmp_str.assign((char *)&len, sizeof(int));
        str_out += tmp_str;
        str_out += itr;
    }
}

void HIRBTreeNode::from_string(const string &str_in)
{
    int len, len1, p_str = 0;
    string tmp_str;
    char _if_leaf;

    tmp_str.reserve(512);

    lhash.clear();
    values.clear();
    children.clear();

    memcpy(&len, str_in.c_str(), sizeof(int));

    p_str = sizeof(int);
    for (int i = 0; i < len; i++)
    {
        memcpy(&len1, str_in.c_str() + p_str, sizeof(int));
        p_str += sizeof(int);
        tmp_str.assign(str_in.c_str() + p_str, len1);
        p_str += len1;
        lhash.emplace_back(tmp_str);
    }

    memcpy(&len, str_in.c_str() + p_str, sizeof(int));

    p_str += sizeof(int);
    for (int i = 0; i < len; i++)
    {
        memcpy(&len1, str_in.c_str() + p_str, sizeof(int));
        p_str += sizeof(int);
        tmp_str.assign(str_in.c_str() + p_str, len1);
        p_str += len1;
        values.emplace_back(tmp_str);
    }

    memcpy(&_if_leaf, str_in.c_str() + p_str, sizeof(_if_leaf));
    p_str += sizeof(char);
    if(_if_leaf)
    {
        if_leaf = true;
        return;
    }
    memcpy(&len, str_in.c_str() + p_str, sizeof(int));

    p_str += sizeof(int);
    for (int i = 0; i < len; i++)
    {
        memcpy(&len1, str_in.c_str() + p_str, sizeof(int));
        p_str += sizeof(int);
        tmp_str.assign(str_in.c_str() + p_str, len1);
        p_str += len1;
        children.emplace_back(tmp_str);
    }
    if_leaf = false;
}

void HIRBTreeNode::split(HIRBTreeNode &sibling_out, const std::string &wedge)
{
    auto p_lhash = lhash.begin(), p_values = values.begin();
    auto p_children = children.begin();
    auto copy_from_lhash = p_lhash, copy_from_values = p_values;
    auto copy_from_children = p_children;

    sibling_out.if_leaf = if_leaf;

    while (1)
    {
        auto p_lhash1 = p_lhash;

        if (*p_lhash == wedge)
            break;

        p_lhash++;
        p_values++;
        if (!if_leaf)
            p_children++;

        if (p_lhash == lhash.end())
            break;
        if ((*p_lhash1 < wedge) && (*p_lhash > wedge))
            break;
    }

    copy_from_lhash = p_lhash;
    copy_from_values = p_values;
    if (!if_leaf)
        copy_from_children = p_children;

    if (p_lhash != lhash.end())
        if (*p_lhash == wedge)
        {
            copy_from_lhash++;
            copy_from_values++;
            if (!if_leaf)
                copy_from_children++;
        }

    sibling_out.lhash.assign(copy_from_lhash, lhash.end());
    sibling_out.values.assign(copy_from_values, values.end());
    if (!if_leaf)
        sibling_out.children.assign(copy_from_children, children.end());

    lhash.erase(p_lhash, lhash.end());
    values.erase(p_values, values.end());
    if (!if_leaf)
    {
        p_children++;
        children.erase(p_children, children.end());
    }
}

string HIRBTreeNode::meage(const HIRBTreeNode &sibling_in)
{
    auto p_children = sibling_in.children.begin();

    if (!if_leaf)
        p_children++;

    lhash.insert(lhash.end(), sibling_in.lhash.begin(), sibling_in.lhash.end());
    values.insert(values.end(), sibling_in.values.begin(), sibling_in.values.end());
    if (!if_leaf)
    {
        children.insert(children.end(), p_children, sibling_in.children.end());
        return *(sibling_in.children.begin());
    }
    else
        return "";
}

void HIRBTreeNode::clear()
{
    lhash.clear();
    values.clear();
    children.clear();
    if_leaf = false;
}