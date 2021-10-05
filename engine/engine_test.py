# -*- coding:utf-8 -*-
#시발 얜 왜 ㅇ안되노오오옹

import os
import sys
import kavcore.k2engine
from kavcore import k2engine

# listvirus의 콜백함수
def listvirus_callback(plugin_name, vnames) :
    print("in engine_test.py")
    for vname in vnames:
        print('%-50s [%s.kmd]' %(vname, plugin_name))

k2=kavcore.k2engine.Engine(debug=True)

if k2.set_plugins('plugins'):   #플러그인 엔진 경로 정의
    kav=k2.create_instance()    #백신 c엔진 인스턴스 생성
    if kav:
        print("[* Success: create instance in engine_test.py]")

        ret = kav.init() # 플러그엔진 초기화
        info = kav.getinfo()

        vlist = kav.listvirus(listvirus_callback) # 플러그인의 바이러스 목록을 출력한다.

        print('[*] Used Callback    : %d in engine_test.py' %len(vlist))

        vlist = kav.listvirus() # 플러그인의 바이러스 목록을 얻는다.
        print('[*] Not Used Callback : %d in engine_test.py' %len(vlist))

        ret, vname, mid, eid = kav.scan('eicar.txt')
        print("===========dummy 변수 확인==============") #self debugging
        print("ret "+str(ret)) #self debugging
        print("vname "+str(vname)) #self debugging
        print("mid "+str(mid)) #self debugging
        print("eid "+str(eid)) #self debugging

        if ret:
            kav.disinfect('eicar.txt', mid, eid)

        kav.uninit() # 플러그인 엔진 종료