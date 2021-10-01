# -*- coding:utf-8 -*-

import re
import kavutil

HTML_KEY_COUNT = 3 # 3개이상 html keyword가 존재하는가?

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
        # pat = r'<\s*html\b|\bdoctype\b|<\s*head\b|<\s*title\b|<\s*meta\b|\bhref\b|<\s*link\b|<\s*body\b|<\s*script\b|<\s*iframe\b|<\?(php\b)?'
        pat = r'<\s*html\b|\bdoctype\b|<\s*head\b|<\s*title\b|<\s*meta\b|\bhref\b|<\s*link\b|<\s*body\b|<\s*script\b|<\s*iframe\b'
        self.p_html = re.compile(pat, re.IGNORECASE)

        # script, iframe, php 키워드
        pat = r'<script.*?>[\d\D]*?</script>|<iframe.*?>[\d\D]*?</iframe>|<\?(php\b)?[\d\D]*?\?>'
        self.p_script = re.compile(pat, re.IGNORECASE)

        # HTML.
        self.p_html_malware = re.compile(r'\?ob_start.+?>\s*<iframe')

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
        info['title'] = 'HTML Engine'  # 엔진 설명
        info['kmd_name'] = 'html'  # 엔진 파일 이름
        info['sig_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info

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

        if filename_ex:
            try:
                if filename_ex.split('/')[-2] == 'HTML':
                    return None
            except IndexError:
                pass

        mm = filehandle

        buf = mm[:4096]
        if kavutil.is_textfile(buf):  # Text 파일인가?
            # HTML 문서
            ret = self.p_html.findall(buf)
            if len(set(ret)) >= HTML_KEY_COUNT:
                fileformat['keyword'] = list(set(ret))  # 존재하는 HTML Keyword 보관
                ret = {'ff_html': fileformat}

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

        # 미리 분석된 파일 포맷중에 HTML 포맷이 있는가?
        if 'ff_html' in fileformat:
            buf = ''

            try:
                with open(filename, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return []

            s_count = 1  # Script 개수
            i_count = 1  # iframe 개수
            p_count = 1  # PHP 개수

            for obj in self.p_script.finditer(buf):
                t = obj.group()
                p = t.lower()

                if p.find('<script') != -1:
                    file_scan_list.append(['arc_html', 'HTML/Script #%d' % s_count])
                    s_count += 1
                elif p.find('<iframe') != -1:
                    file_scan_list.append(['arc_html', 'HTML/IFrame #%d' % i_count])
                    i_count += 1
                elif p.find('<?') != -1:
                    file_scan_list.append(['arc_html', 'HTML/PHP #%d' % p_count])
                    p_count += 1

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_html':
            buf = ''

            try:
                with open(arc_name, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return None

            s_count = 1  # Script 개수
            i_count = 1  # iframe 개수
            p_count = 1  # PHP 개수

            for obj in self.p_script.finditer(buf):
                t = obj.group()
                pos = obj.span()
                p = t.lower()

                if p.find('<script') != -1:
                    k = 'HTML/Script #%d' % s_count
                    s_count += 1
                elif p.find('<iframe') != -1:
                    k = 'HTML/IFrame #%d' % i_count
                    i_count += 1
                elif p.find('<?') != -1:
                    k = 'HTML/PHP #%d' % p_count
                    p_count += 1
                else:
                    k = ''

                if k == fname_in_arc:
                    data = buf[pos[0]:pos[1]]
                    return data

        return None