# -*- coding:utf-8 -*-

import os
import StringIO
import datetime

import k2kmdfile
import k2rsa

#Engine 클래스
class Engine:
    #클래스 초기화
    def __init__(self, debug=False):
        self.debug=debug    #디버깅 여부
        self.plugins_path=None  #플러그인 경로

        self.kmdfiles=[]
        self.kmd_modules=[]

        self.max_datetime = datetime.datetime(1980,1,1,0,0,0,0)


    #주어진 경로에서 플러그인 엔진 로딩 준비
    def set_plugins(self,plugins_path):
        self.plugins_path=plugins_path  #플러그인 경로 저장

        #공개키 로딩
        pu = k2rsa.read_key(os.path.join(plugins_path, 'key.pkr'))
        if not pu:
            return False

        #우선순위 알아내기
        ret = self.__get_kmd_list(os.path.join(plugins_path, 'cloudbread.kmd'), pu)
        if not ret: #로딩할 kmd 파일이 없을 시
            return False

        if self.debug:
            print("[*] Cloudbread. kmd: ")
            print('     '+str(self.kmdfiles))

        # 우선순위대로 KMD 파일을 로딩한다.
        for kmd_name in self.kmdfiles:
            #print(kmd_name) #우선순위 확인
            kmd_path = plugins_path+os.sep+kmd_name
            #print(kmd_path) #kmd파일위치 확인
            k=k2kmdfile.KMD(kmd_path, pu)   #모든 kmd 파일을 복호화
            if k: #복호화 성공 확인
                print(str(kmd_name)+"복호화 성공")
            module=k2kmdfile.load(kmd_name.split('.')[0], k.body)

            if module:  # 메모리 로딩 성공
                self.kmd_modules.append(module)
                # 메모리 로딩에 성공한 KMD에서 플러그 엔진의 시간 값 읽기
                self.__get_last_kmd_build_time(k)

        if self.debug:
            print("[*] kmd_modules: ")
            print('     '+str(self.kmd_modules))
            print("[*] Last updated %s UTC"%self.max_datetime.ctime())

        return True

    # ---------------------------------------------------------------------
    # __get_last_kmd_build_time(self, kmd_info)
    # 복호화 된 플러그인 엔진의 빌드 시간 값 중 최신 값을 보관한다.
    # 입력값 : kmd_info - 복호화 된 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def __get_last_kmd_build_time(self, kmd_info):
        d_y, d_m, d_d = kmd_info.date
        t_h, t_m, t_s = kmd_info.time
        t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

        if self.max_datetime < t_datetime:
            self.max_datetime = t_datetime

    # ---------------------------------------------------------------------
    # create_instance(self)
    # 백신 엔진의 인스턴스를 생성한다.
    # ---------------------------------------------------------------------

    def create_instance(self):
        ei = EngineInstance(self.plugins_path, self.max_datetime, self.debug)
        if ei.create(self.kmd_modules):
            return ei
        else:
            return None

    #플러그인 엔진의 로딩 우선순위 알아내는 함수
    def __get_kmd_list(self, cloudbread_kmd_file, pu):
        kmdfiles=[] #우선순위 목록

        k=k2kmdfile.KMD(cloudbread_kmd_file, pu)    #cloudbread.kmd 파일 복호화

        if k.body:  #cloudbread.kmd가 읽혔는지?
            msg=StringIO.StringIO(k.body)

            while True:
                line=msg.readline().strip() #엔터 제거

                if not line:    #읽을 내용이 없으면 종료
                    break
                elif line.find('.kmd') != -1:   # kmd가 포함되어 있으면 우선순위 목록에 추가
                    kmdfiles.append(line)
                else:
                    continue

        if len(kmdfiles):   #우선순위 목록에 하나라도 있다면 성송
            self.kmdfiles=kmdfiles
            return True
        else:
            return False



# -------------------------------------------------------------------------
# EngineInstance 클래스
# -------------------------------------------------------------------------
class EngineInstance:
    # ---------------------------------------------------------------------
    # __init__(self, plugins_path, temp_path, max_datetime, verbose=False)
    # 클래스를 초기화 한다.
    # 인자값 : plugins_path - 플러그인 엔진 경로
    #         temp_path    - 임시 폴더 클래스
    #         max_datetime - 플러그인 엔진의 최신 시간 값
    #         verbose      - 디버그 여부
    # ---------------------------------------------------------------------

    def __init__(self, plugins_path, max_datetime, debug=False):
        self.debug = debug  # 디버깅 여부
        self.plugins_path = plugins_path  # 플러그인 경로
        self.max_datetime = max_datetime

        self.kavmain_inst=[] # 모든 플러그인의 KavMain 인스턴스

    # ---------------------------------------------------------------------
    # init(self, callback_fn)
    # 플러그인 엔진 전체를 초기화한다.
    # 입력값 : callback_fn - 콜백함수 (생략 가능)
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------

    def init(self):
        t_kavmain_inst=[] # 최종 인스턴스 리스트

        if self.debug:
            print('[*] KavMain.init() :')

        for inst in self.kavmain_inst:
            try:
                # 플러그인 엔진의 init 함수 호출
                ret = inst.init(self.plugins_path)
                if not ret : # 성공
                    t_kavmain_inst.append(inst) # 임시 최종 인스턴스로 등록

                    if self.debug:
                        print ('    [-] %s.uninit() : %d' % (inst.__module__, ret))
            except AttributeError:
                continue

        self.kavmain_inst = t_kavmain_inst # 최종 kavmain 인스턴스 등록

        if len(self.kavmain_inst):
            if self.debug:
                print ('[*] Count of KavMain.init() : %d' % (len(self.kavmain_inst)))
            return True
        else:
            return False



    # 백신 엔진의 인스턴스를 생성
    # 인자값 : kmd_modules - 메모리에 로딩된 KMD 모듈 리스트
    # 리턴값 : 성공 여부
    def create(self, kmd_modules):  # 백신 엔진 인스턴스를 생성
        for mod in kmd_modules:
            try:
                t = mod.KavMain()  # 각 플러그인 KavMain 인스턴스 생성
                self.kavmain_inst.append(t)
            except AttributeError:  # KavMain 클래스 존재하지 않음
                continue

        if len(self.kavmain_inst):  # KavMain 인스턴스가 하나라도 있으면 성공
            if self.debug:
                print('[*] Count of KavMain : %d' % (len(self.kavmain_inst)))
            return True
        else:
            return False
    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진 전체를 종료한다.
    # ---------------------------------------------------------------------

    def uninit(self):
        if self.debug:
            print ('[*] KavMain.uninit() :')

        for inst in self.kavmain_inst:
            try:
                ret = inst.uninit()
                if self.debug:
                    print ('    [-] %s.uninit() : %d' % (inst.__module__, ret))
            except AttributeError:
                continue

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진 정보를 얻는다.
    # 리턴값 : 플러그인 엔진 정보 리스트
    # ---------------------------------------------------------------------

    def getinfo(self):
        ginfo = []  # 플러그인 엔진 정보를 담는다.

        if self.debug:
            print('[*] KavMain.getinfo() :')

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()
                ginfo.append(ret)

                if self.verbose:
                    print('    [-] %s.getinfo() :' % inst.__module__)
                    for key in ret.keys():
                        print ('        - %-10s : %s' % (key, ret[key]))
            except AttributeError:
                continue

        return ginfo