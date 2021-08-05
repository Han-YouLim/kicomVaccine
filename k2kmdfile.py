#-*-coding:utf-8 -*-

import hashlib
import os
import py_compile
import random
import shutil
import struct
import sys
import zlib
import k2rc4
import k2rsa
import k2timelib

'''
---------------------------------------------------------------------------
# make(src_fname)
# rsa 개인키를 ㅣ용해서 주어진 파일을 암호화하여 KMD 파일을 생성한다.

# 인자값 : src_fname - 암호화 대상파일
# 리턴값 : KMD 파일 생성 성공 여부
---------------------------------------------------------------------------
'''
def make(src_fname, debug = False) :
    # 암호화 대상 파일을 컴파일 또는 복사해서 준비한다.
    fname = src_fname # 암호화 대상 파일

    if fname.split('.')[1] =='py': # 파이썬 파일을 컴파일한다
        py_compile.compiile(fname) # 컴파일
        pyc_name = fname + 'c' # 컴파일 이후 파일명
    else:
        pyc_name = fname.split('.')[0]+'.pyc'
        shutil.copy(fname,pyc_name)

    # Simple RSA를 사용하기 위해 공개키와 개인키를 로딩한다.

    # 공개키를 로딩한다.
    rsa_pu = k2rsa.read_key('key.pkr')
    # print 'pkr : ', rsa_pu

    # 개인키를 로딩한다.
    rsa_pr = k2rsa.read_key('key.skr')
    # print 'skr : ', rsa_pr

    if not (rsa_pr and rsa_pu): # 키 파일을 찾을 수 없다.
        print('ERRIR : Canot find the Key files!')
    return False

    # KMD 파일을 생성한다.
    # 헤더 : 시그니처(KAVM) +예약 영역 : [[KAVM][날짜][시간]]
    # 시그니처를 추가한다.

    kmd_data = 'KAVM'

    # 현재 날짜와 시간을 구한다.
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    # 날짜와 시간 값을 2바이트로 변경한다.
    val_date = struct.pack('<H',ret_date)
    val_time = struct.pack('<H',ret_time)

    reserved_buf = val_date+val_time+(chr(0)*28) #예약 영역

    # 날짜/시간 값이 포함된 예약 영역을 만들어 추가한다.
    kmd_data +=reserved_buf

    # 본문 : [[개인키로 암호화된 RC4 키][RC4로 암호화된 파일]]
    random.seed()

    while 1:
        tmp_kmd_data ='' # 임시 본문 데이터

        # RC4 알고리즘에 사용할 128BIT 랜덤키 생성
        key =''




