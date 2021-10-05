# -*- coding:utf-8 -*-

import os
from engine.plugins import cryptolib

class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename):  # 악성코드 검사
        try:
            mm = filehandle

            size = os.path.getsize(filename)  # 검사 대상 파일 크기를 구한다.
            if size == 68:  # EICAR Test 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5 = cryptolib.md5(mm[:68])

                # 파일에서 얻은 해시 값과 EICAR Test 악성코드의 해시 값이 일치하는가?
                if fmd5 == '44d88612fea8a8f36de82e1278abb02f':
                    return True, 'EICAR-Test-File (not a virus)', 0
        except IOError:
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1

    # 악성코드를 치료한다.
    def disinfect(self, filename, malware_id):  # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except Exception as e:
            print("eicar.py 에러: "+str(e)) #self debugging
            pass

        return False  # 치료 실패 리턴

    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = list()  # 리스트형 변수 선언

        vlist.append('EICAR-Test-File (not a virus)')  # 진단/치료하는 악성코드 이름 등록

        return vlist

    # getinfo(self)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  # 제작자
        info['version'] = '0,0'  # 버전
        info['title'] = 'EICAR Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'eicar'  # 엔진 파일 이름
        info['sig_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info