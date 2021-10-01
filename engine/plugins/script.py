# -*- coding:utf-8 -*-

import re
import os
import hashlib
import kernel
import kavutil


KICOMAV_BAT_MAGIC = '<KicomAV:BAT>'


# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        # text 포맷으로 된 파일 포맷 확인하기
        self.p_text_format = re.compile(r'\s*@?(\w+)', re.IGNORECASE)

        # 파일 시작이 <script, <iframe인지 확인하는 정규표현식
        self.p_script_head = re.compile(r'\s*<\s*(script|iframe)', re.IGNORECASE)

        # scrip/iframe 정보가 html 내부에 있는지 확인하는 정규표현식
        s = r'<\s*(script|iframe).*?>([\d\D]*?)<\s*/(script|iframe)\s*>'
        self.p_script_in_html = re.compile(s, re.IGNORECASE)

        # 주석문 및 공백 제거를 위한 정규표현식
        self.p_http = re.compile(r'https?://')
        # self.p_script_cmt1 = re.compile(r'//.*|/\*[\d\D]*?\*/')
        self.p_script_cmt1 = re.compile(r'//.*')
        self.p_script_cmt2 = re.compile(r'/\*.*?\*/', re.DOTALL)
        self.p_script_cmt3 = re.compile(r'(#|\bREM\b).*', re.IGNORECASE)
        self.p_space = re.compile(r'[\s]')

        # BAT 주석문
        self.p_bat_cmt1 = re.compile(r'\bREM\s+.*', re.IGNORECASE)
        self.p_bat_cmt2 = re.compile(r'[\^\`]', re.IGNORECASE)

        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Script Engine'  # 엔진 설명
        info['kmd_name'] = 'script'  # 엔진 파일 이름
        info['sig_num'] = kavutil.handle_pattern_md5.get_sig_num('script')  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = kavutil.handle_pattern_md5.get_sig_vlist('script')
        vlist.sort()
        return vlist

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        fileformat = {}  # 포맷 정보를 담을 공간

        mm = filehandle

        buf = mm[:4096]

        if kavutil.is_textfile(buf):  # Text 파일인가?
            obj = self.p_text_format.match(buf)  # 첫 시작 단어로 파일 포맷 인식하기
            if obj:
                t = obj.groups()[0].lower()
                if t in ['cd', 'echo']:
                    return {'ff_bat': 'BAT'}
            elif mm[:13] == KICOMAV_BAT_MAGIC:
                return {'ff_bat': 'BAT'}

            obj = self.p_script_head.match(buf)
            if obj:
                # 내부 스크립트가 존재하나?
                obj_script = self.p_script_in_html.search(mm[:])

                if obj_script:
                    buf_strip = obj_script.groups()[1].strip()
                    n_buf_stript = len(buf_strip)
                    fileformat['size'] = n_buf_stript

                    if n_buf_stript:  # 내부 스크립트
                        if obj_script.groups()[0].lower() == 'script':
                            ret = {'ff_script': fileformat}
                        else:
                            ret = {'ff_iframe': fileformat}
                    else:  # 외부 스크립트
                        if obj_script.groups()[0].lower() == 'script':
                            ret = {'ff_script_external': fileformat}
                        else:
                            ret = {'ff_iframe_external': fileformat}
                else:
                    # 발견하지 못했다면 외부 스크립트일 가능성이 크다
                    fileformat['size'] = 0  # 외부 스크립트

                    if obj.group().lower().find('script') != -1:
                        ret = {'ff_script_external': fileformat}
                    else:
                        ret = {'ff_iframe_external': fileformat}

                return ret

        return None

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ff_script 포맷이 있는가?
        if 'ff_script' in fileformat:
            # TODO : VBScript에 대한 처리도 필요함
            file_scan_list.append(['arc_script', 'JavaScript'])
        elif 'ff_iframe' in fileformat:
            file_scan_list.append(['arc_iframe', 'IFrame'])
        elif 'ff_bat' in fileformat:
            file_scan_list.append(['arc_bat', 'BAT'])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id in ['arc_script', 'arc_iframe', 'arc_bat']:
            try:
                with open(arc_name, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return None

            if arc_engine_id in ['arc_script', 'arc_iframe']:
                obj = self.p_script_in_html.search(buf)
                if obj:
                    data = obj.groups()[1]
                    return data

            elif arc_engine_id == 'arc_bat':
                buf = self.p_bat_cmt1.sub('', buf)
                data = self.p_bat_cmt2.sub('', buf)
                return KICOMAV_BAT_MAGIC + data

        return None