# -*- coding:utf-8 -*-
#시발 얜 왜 ㅇ안되노오오옹

import os
import sys

import kavcore.k2engine

k2=kavcore.k2engine.Engine(debug=True)
k2.set_plugins('plugins')

'''
if k2.set_plugins('plugins'):   #플러그인 엔진 경로 정의
    kav=k2.create_instance()    #백신 엔진 인스턴스 생성
    if kav:
        print("[* Success: create instance]")
'''