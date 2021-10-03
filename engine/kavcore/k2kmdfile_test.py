# -*- coding:utf-8 -*-

import k2rsa
import k2kmdfile


#씨이ㅣ이이발 왜 안되노;;

k2rsa.create_key('key.pkr', 'key.skr')

ret = k2kmdfile.make('../../readme.txt')

if ret:
    pu= k2rsa.read_key('../plugins/key.pkr')
    k= k2kmdfile.KMD('readme.kmd', pu)
    print(k.body)
else:
    print("fail!")