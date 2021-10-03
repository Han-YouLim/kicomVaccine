# -*- coding:utf-8 -*-

import k2rc4

#k2rc4 테스트 코드
if __name__=='__main__':
    rc4= k2rc4.RC4()
    rc4.set_key('sung04156!')   #암호 설정
    t1=rc4.crypt('hello Cloudbread!')   #암호화

    rc4= k2rc4.RC4()
    rc4.set_key('sung04156!')   #암호설정
    t2=rc4.crypt(t1)    #복호화
    print(t1)    #암호화 결과 확인
    print(t2)    #복호화 결과 확인