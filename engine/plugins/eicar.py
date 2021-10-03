# -*- coding:utf-8 -*-

import os
import crytolib

# KavMain 클래스
class KavMain:

    def init(self, plugins_path):  # 플러그인 엔진 초기화
        return 0  # 성공

    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # 악성코드 검사
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    def scan(self, filehandle, filename):
        try:
            mm = filehandle

            size = os.path.getsize(filename)  # 검사 대상 파일 크기를 구한다.
            if size == 68:  # EICAR Test 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5=crytolib.md5(mm[:68])

                # 파일에서 얻은 해시 값과 EICAR Test 악성코드의 해시 값이 일치하는가?
                if fmd5 == '44d88612fea8a8f36de82e1278abb02f':
                    return True, 'EICAR-Test-File (not a virus)', 0
        except IOError:
            pass

        # 악성코드를 발견하지 못했음을 리턴 -> 악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
        return False, '', -1


    # 악성코드 치료
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    def disinfect(self, filename, malware_id):
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0 -> 악성코드임
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료
        except IOError:
            pass

        return False  # 치료 실패

    # 진단/치료 가능한 악성코드의 리스트
    def listvirus(self):
        vlist = list()

        vlist.append('EICAR-Test-File (not a virus)')  # 진단/치료하는 악성코드 이름 등록

        return vlist

    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  # 제작자
        info['version'] = '0,0'  # 버전
        info['title'] = 'EICAR Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'eicar'  # 엔진 파일 이름
        info['sig_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info