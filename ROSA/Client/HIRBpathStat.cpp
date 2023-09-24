#include "HIRBpathStat.h"
#include "../CommonUtils.h"

void HIRBpathStat::setup(int height)
{
    id0 = id0p = id1 = id1p = "";
    cid0 = cid0p = cid1 = cid1p = "";
    label_hash = "";
    found = true;
    l = 0;
    H = height;
    v0.clear();
    v1.clear();
}

void HIRBpathStat::dump_data(FILE *f_out)
{
    std::string str;
    int tmp_int;

    save_string(f_out, id0);
    save_string(f_out, id0p);
    save_string(f_out, id1);
    save_string(f_out, id1p);
    save_string(f_out, cid0);
    save_string(f_out, cid1);
    save_string(f_out, cid0p);
    save_string(f_out, cid1p);
    save_string(f_out, label_hash);
    v0.to_string(str);
    save_string(f_out, str);
    v1.to_string(str);
    save_string(f_out, str);
    if (found)
        tmp_int = 1;
    else
        tmp_int = 0;
    fwrite(&tmp_int, sizeof(tmp_int), 1, f_out);
    fwrite(&l, sizeof(l), 1, f_out);
    fwrite(&H, sizeof(H), 1, f_out);
}

void HIRBpathStat::load_data(FILE *f_in)
{
    std::string str;
    int tmp_int;

    load_string(id0, f_in);
    load_string(id0p, f_in);
    load_string(id1, f_in);
    load_string(id1p, f_in);
    load_string(cid0, f_in);
    load_string(cid1, f_in);
    load_string(cid0p, f_in);
    load_string(cid1p, f_in);
    load_string(label_hash, f_in);
    v0.clear();
    load_string(str, f_in);
    v0.from_string(str);
    v1.clear();
    load_string(str, f_in);
    v1.from_string(str);
    fread(&tmp_int, sizeof(tmp_int), 1, f_in);
    if (tmp_int)
        found = true;
    else
        found = false;
    fread(&l, sizeof(l), 1, f_in);
    fread(&H, sizeof(H), 1, f_in);
}