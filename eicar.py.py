#-*-coding:utf-8 -*-
import os
import hashlib

class KavMain:

    '''
    ---------------------------------------------------------------------------
        <플러그인 엔진 초기화 init 함수>
        플러그인 엔진 초기화 시점에 백신 커널에 의해 호출
        플러그인 엔진은 이 시점에 각자의 악성코드 패턴 파일 로딩, 필요한 메모리 활보 등의 일 처리
    ---------------------------------------------------------------------------
    '''
    def init(self, plugins_path):
        return 0    #플러그인 엔진 초기화 성공

    '''
    ---------------------------------------------------------------------------
        <플러그인 엔진 종료 uninit 함수>
        백신 커널이 플러그인 엔진에게 잠시 뒤 백신 엔진 전체가 종료될 것을 알려주는 시점에 호출
    ---------------------------------------------------------------------------
    '''
    def uninit(self):
        return 0    #플러그인 엔진 종료 성공

    #악성코드 검사
    def scan(self, filehandle, filename):
        try:
            mm=filehandle

            size=os.path.getsize(filename)
            if size==68:
                m=hashlib.md5()
                m.update(mm[:68])
                fmd5-m.hexdigest()
                if fmd5=='44D88612FEA8A8F36DE82E1278ABB02F':
                    return True, 'EICAR-Test-File(not a virus)', 0
        except IOError:
            pass
        return False, '', -1    #악성코드 발견 X

    #악성코드 치료
    def disinfect(self, filename, malware_id):
        try:
            if malware_id==0:   #scan으로부터 받은 ID 값이 0인지 판단
                os.remove(filename) #파일 삭제
                return True #치료 완료!
        except IOError:
            pass
        return False    #치료 실패 ToT

    #플러그인 엔진이 진단/치료 가능한 악성코드의 리스트 명시(클라이언트에게 제공용도로 사용가능)
    def listvirus(self):
        vlist=list()
        vlist.append('EICAR-Test-File (not a virus)')
        return vlist


    #플러그인 엔진의 주요 정보 명시
    def getinfo(self):
        info=dict()

        info['author']='SoaLee'
        info['version']='1.0'
        info['title']='EICAR Scan Engine'
        info['kmd_name']='eicar'

        return info
