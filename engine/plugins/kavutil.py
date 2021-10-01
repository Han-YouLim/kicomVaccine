# -*- coding:utf-8 -*-

import re

p_text = re.compile(r'[\w\s!"#$%&\'()*+,\-./;:<=>?@\[\\\]\^_`{\|}~]')

# -------------------------------------------------------------------------
# is_textfile(buf)
# 주어진 버퍼가 Text인지 아닌지를 판단한다.
# 입력값 : buf - 버퍼
# 리턴값 : Text 유무 (True, False)
# -------------------------------------------------------------------------
def is_textfile(buf):
    n_buf = len(buf)

    n_text = len(p_text.findall(buf))

    if n_text / float(n_buf) > 0.8:  # 해당 글자가 차지하는 비율이 80% 이상인가?
        return True

    return False