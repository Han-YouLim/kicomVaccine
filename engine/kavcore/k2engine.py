# -*- coding:utf-8 -*-
import glob
import mmap
import os
import StringIO
import datetime
import types

import k2kmdfile
import k2rsa

#Engine 클래스
from engine.kavcore import k2file, k2const


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
            kmd_path = plugins_path+os.sep+kmd_name
            k=k2kmdfile.KMD(kmd_path, pu)   #모든 kmd 파일을 복호화
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

    def __init__(self, plugins_path, temp_path, max_datetime,debug=False):
        self.debug = debug  # 디버깅 여부
        self.plugins_path = None  # 플러그인 경로

        self.kmdfiles = []
        self.kmd_modules = []
        self.options = {}  # 옵션
        self.set_options()  # 기본 옵션 설정
        self.kavmain_inst = []  # 모든 플러그인의 KaVMain 인스턴스
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)
        self.result = {}
        self.identified_virus = set()

    def set_options(self,options=None):
        if options:
            self.options['opt_list'] = options.opt_list
        else:
            self.options['opt_list'] = False
        return True

    def set_result(self):
        self.result['Folders'] = 0
        self.result['Files'] = 0
        self.result['Infected_files'] = 0
        self.result['Identified_viruses'] = 0
        self.result['IO_errors'] = 0

    def get_result(self):
        self.result['Identified_viruses'] = len(self.identified_virus)
        return self.result

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

                if self.debug:
                    print('    [-] %s.getinfo() :' % inst.__module__)
                    for key in ret.keys():
                        print ('        - %-10s : %s' % (key, ret[key]))
            except AttributeError:
                continue

        return ginfo

    # ---------------------------------------------------------------------
    # listvirus(self, *callback)
    # 플러그인 엔진이 진단/치료 할 수 있는 악성코드 목록을 얻는다.
    # 입력값 : callback - 콜백함수 (생략 가능)
    # 리턴값 : 악성코드 목록 (콜백함수 사용시 아무런 값도 없음)
    # ---------------------------------------------------------------------

    def listvirus(self, *callback):
        vlist = []  # 진단/치료 가능한 악성코드 목록

        argc = len(callback)  # 가변인자 확인

        if argc == 0:  # 인자가 없으면
            cb_fn = None
        elif argc == 1:  # callback 함수가 존재하는지 체크
            cb_fn = callback[0]
        else:  # 인자가 너무 많으면 에러
            return []

        if self.debug:
            print ('[*] KavMain.listvirus() :')

        for inst in self.kavmain_inst:
            try:
                ret = inst.listvirus()

                # callback 함수가 있다면 callback 함수 호출
                if isinstance(cb_fn, types.FunctionType):
                    cb_fn(inst.__module__, ret)
                else:  # callback 함수가 없으면 악성코드 목록을 누적하여 리턴
                    vlist += ret

                if self.debug:
                    print ('    [-] %s.listvirus() :' % inst.__module__)
                    for vname in ret:
                        print ('        - %s' % vname)
            except AttributeError:
                continue

        return vlist

    # ---------------------------------------------------------------------
    # scan(self, filename)
    # 플러그인 엔진에게 악성코드 치료를 요청한다.
    # 입력값 : filename   - 악성코드 치료 대상 파일 이름
    #          malware_id - 감염된 악성코드 ID
    #          engine_id  - 악성코드를 발견한 플러그인 엔진 ID
    # 리턴값 : 악성코드 치료 성공 여부
    # ---------------------------------------------------------------------
    def scan(self, filename, *callback):

        scan_callback_fn = None #악성코드 검사 콜백 함수
        disinfect_callback_fn = None #악성코드 치료 콜백 함수
        update_callback_fn = None #악성코드 압축 최종 치료 콜백 함수

        # 악성코드 검사 결과
        ret_value = {
            'filename': '',  # 파일 이름
            'result': False,  # 악성코드 발견 여부
            'virus_name': '',  # 발견된 악성코드 이름
            'virus_id': -1,  # 악성코드 ID
            'engine_id': -1  # 악성코드를 발견한 플러그인 엔진 ID
        }

        try:
            scan_callback_fn = callback[0]
            disinfect_callback_fn = callback[1]
            update_callback_fn = callback[3]
        except IndexError:
            pass

        argc = len(callback)

        # 1. 검사 대상 리스트에 파일을 등록
        file_info = k2file.FileStruct(filename)
        file_scan_list = [file_info]

        while len(file_scan_list):
            try:
                t_file_info = file_scan_list.pop(0) # 검사 대상 파일 하나를 가짐
                real_name = t_file_info.get_filename()  #real_filename을 가져옴

                # 폴더면 내부 파일리스트만 검사 대상 리스트에 등록
                if os.path.isdir(real_name):
                    # 폴더 등을 처리할 때를 위해 뒤에 붇는 os.sep는 우선 제거
                    if real_name[-1] == os.sep:
                        real_name = real_name[:-1]

                    # 콜백 호출 또는 검사 리턴값 생성
                    ret_value['result'] = False  # 폴더이므로 악성코드 없음
                    ret_value['filename'] = real_name  # 검사 파일 이름
                    ret_value['file_struct'] = t_file_info

                    self.result['Folders'] += 1

                    if self.options['opt_list']:  # 옵션 내용 중 모든 리스트 출력인가?

                        if isinstance(scan_callback_fn, types.FunctionType): #콜백함수가 존재하는가?
                            scan_callback_fn(ret_value) #콜백 함수 호출

                    flist = glob.glob(real_name+os.sep+ '*')
                    tmp_flist=[]

                    for rfname in flist:
                        tmp_info = k2file.FileStruct(rfname)
                        tmp_flist.append(tmp_info)

                    file_scan_list = tmp_flist + file_scan_list #생성된 목록은 file_scan_list 맨 앞에 삽입


                # 검사 대상이 파일인가? 압축 해제 대상인가?
                elif os.path.isfile(real_name) or t_file_info.is_archive():
                    self.result['Files'] += 1  # 파일 개수 카운트

                    ret = self.unarc(t_file_info) #압축된 파일이면 압축 해제
                    if ret:
                        t_file_info = ret

                    #2. 포맷 분석
                    ff = self.format(t_file_info)

                    # 파일로 악성코드 검사
                    ret, vname, mid, eid = self.__scan_file(t_file_info, ff)

                    if ret:
                        self.result['Infected_files'] += 1
                        self.identified_virus.update([vname])

                    ret_value['result'] = ret  # 악성코드 발견 여부
                    ret_value['engine_id'] = eid # 엔진 ID
                    ret_value['virus_name'] = vname  # 에러 메시지로 대체
                    ret_value['virus_id'] = mid  # 악성코드 ID
                    ret_value['filename'] = t_file_info  # 검사 파일 이름

                    if ret_value['result']: #악성 코드 발견인가?
                        if isinstance(scan_callback_fn, types.FunctionType):
                            action_type = scan_callback_fn(ret_value)

                            if action_type == k2const.K2_ACTION_QUIT:
                                return 0

                            self.__disinfect_process(ret_value, disinfect_callback_fn, action_type)
                    else:
                        if self.options['opt_list']:  # 옵션 내용 중 모든 리스트 출력인가?
                            if isinstance(scan_callback_fn, types.FunctionType):
                                scan_callback_fn(ret_value)

                    self.__update_process(t_file_info, update_callback_fn)


                    #이미 해당 파일이 악성 코드라고 판명되었다면
                    #그 파일을 압축 해제해서 내부를 볼 필요 없다.
                    #따라서 악성코드가 아닌 경우만 검사
                    if not ret:
                        #압축파일이면 검사 대상 리스트에 추가
                        arc_file_list = self.arclist(t_file_info, ff)
                        if len(arc_file_list):
                            file_scan_list = arc_file_list + file_scan_list

            except KeyboardInterrupt:
                return 1


        self.__update_process(None, update_callback_fn, True)
        return 0



    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id, engine_id)
    # 플러그인 엔진에게 악성코드 치료를 요청한다.
    # 입력값 : filename   - 악성코드 치료 대상 파일 이름
    #          malware_id - 감염된 악성코드 ID
    #          engine_id  - 악성코드를 발견한 플러그인 엔진 ID
    # 리턴값 : 악성코드 치료 성공 여부
    # ---------------------------------------------------------------------

    def disinfect(self, filename, malware_id, engine_id):
        ret = False

        if self.debug:
            print ('[*] KavMain.disinfect() :')

        try:
            # 악성코드를 진단한 플러그인 엔진에게만 치료를 요청한다.
            inst = self.kavmain_inst[engine_id]
            ret = inst.disinfect(filename, malware_id)

            if self.debug:
                print ('    [-] %s.disinfect() : %s' % (inst.__module__, ret))
        except AttributeError:
            pass

        return ret
    # ---------------------------------------------------------------------
    # getversion(self)
    # 전체 플러그인 엔진의 최신 버전 정보를 전달한다.
    # ---------------------------------------------------------------------
    def get_version(self):
        return self.max_datetime

    # ---------------------------------------------------------------------
    # get_signum(self)
    # 백신 엔진이 진단/치료 간으한 아성코드 수를 얻는다.
    # ---------------------------------------------------------------------
    def get_signum(self):
        signum = 0 # 진단/치료 가능한 악성코드 수

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()

                # 플러그인 엔진 정보에 진단/치료 가능 악성코드 수 누적
                if 'sig_num' in ret:
                    signum += ret['sig_num']
            except AttributeError:
                continue
        return signum

    # ---------------------------------------------------------------------
    # __scan_file(self, file_struct, fileformat)
    # 플러그인 엔진에게 악성코드 검사를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    #         format      - 미리 분석한 파일 포맷 분석 정보
    # 리턴값 : (악성코드 발견 유무, 악성코드 이름, 악성코드 ID, 악성코드 검사 상태, 플러그인 엔진 ID)
    # ---------------------------------------------------------------------
    def __scan_file(self, filename):

        if self.debug:
            print('[*] KavMain.__scan_file() :')

        try:
            ret = False
            vname = ''
            mid = -1
            eid = -1

            fp = open(filename,'rb')
            mm = mmap.mmap(fp.fileno(),0,access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret, vname, mid = inst.scan(mm, filename)
                    if ret:  # 악성코드 발견하면 추가 악성코드 검사를 중단한다.
                        eid = i  # 악성코드를 발견한 플러그인 엔진 ID

                        if self.debug:
                            print('    [-] %s.__scan_file() : %s' % (inst.__module__, vname))

                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()

            if fp:
                fp.close()

            return ret, vname, mid, eid
        except IOError:
            pass

        return False, '', -1, -1

    # ---------------------------------------------------------------------
    # __disinfect_process(self, ret_value, action_type)
    # 악성코드를 치료한다.
    # 입력값 : ret_value            - 악성코드 검사 결과
    #          action_type            - 악성코드 치료 or 삭제 처리 여부
    # 리턴값 : 치료 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def __disinfect_process(self, ret_value, disinfect_callback_fn, action_type):
        if action_type == k2const.K2_ACTION_IGNORE:  # 치료에 대해 무시
            return

        t_file_info = ret_value['file_struct']  # 검사 파일 정보
        mid = ret_value['virus_id']
        eid = ret_value['engine_id']

        d_fname = t_file_info.get_filename()
        d_ret = False

        if action_type == k2const.K2_ACTION_DISINFECT:  # 치료 옵션이 설정되었나?
            d_ret = self.disinfect(d_fname, mid, eid)
            if d_ret:
                self.result['Disinfected_files'] += 1  # 치료 파일 수
        elif action_type == k2const.K2_ACTION_DELETE:  # 삭제 옵션이 설정되었나?
            try:
                os.remove(d_fname)
                d_ret = True
                self.result['Deleted_files'] += 1  # 삭제 파일 수
            except (IOError, OSError) as e: #//
                d_ret = False

        t_file_info.set_modify(d_ret)  # 치료(수정/삭제) 여부 표시

        if isinstance(disinfect_callback_fn, types.FunctionType):
            disinfect_callback_fn(ret_value, action_type)

        return d_ret

    # ---------------------------------------------------------------------
    # __update_process(self, file_struct, immediately_flag=False)
    # update_info를 갱신한다.
    # 입력값 : file_struct        - 파일 정보 구조체
    #          immediately_flag   - update_info 모든 정보 갱신 여부
    # ---------------------------------------------------------------------
    def __update_process(self, file_struct, update_callback_fn, immediately_flag=False):
        # 압축 파일 정보의 재압축을 즉시하지 않고 내부 구성을 확인하여 처리한다.
        if immediately_flag is False:
            if len(self.update_info) == 0:  # 아무런 파일이 없으면 추가
                self.update_info.append(file_struct)
            else:
                n_file_info = file_struct  # 현재 작업 파일 정보
                p_file_info = self.update_info[-1]  # 직전 파일 정보

                # 마스터 파일이 같은가? (압축 엔진이 있을때만 유효)
                if p_file_info.get_master_filename() == n_file_info.get_master_filename():
                    if p_file_info.get_level() <= n_file_info.get_level():
                        # 마스터 파일이 같고 계속 압축 깊이가 깊어지면 계속 누적
                        self.update_info.append(n_file_info)
                    else:
                        ret_file_info = self.__update_arc_file_struct(p_file_info)
                        self.update_info.append(ret_file_info) #rufhrkvkdlf cnrk
                        self.update_info.append(n_file_info) #ekdma vkdfl cnrk
                else:
                    immediately_flag = True

        # 압축 파일 정보를 이용해 즉시 압축하여 최종 마스터 파일로 재조립한다.
        if immediately_flag and len(self.update_info) > 1:
            ret_file_info = None
        while len(self.update_info):
            p_file_info = self.update_info[-1]
            ret_file_info = self.__update_arc_file_struct(p_file_info)

            if len(self.update_info):
                self.update_info.append(ret_file_info)
        if isinstance(update_callback_fn, types.FunctionType) and ret_file_info:
            update_callback_fn(ret_file_info)


    # ---------------------------------------------------------------------
    # unarc(self, file_struct)
    # 플러그인 엔진에게 압축 해제를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    # 리턴값 : 압축 해제된 파일 정보 or None
    # ---------------------------------------------------------------------
    def unarc(self, file_struct):
        rname_struct = None

        try:
            if file_struct.is_archive():  # 압축인가?
                arc_engine_id = file_struct.get_archive_engine_name()  # 엔진 ID
                arc_name = file_struct.get_archive_filename()
                name_in_arc = file_struct.get_filename_in_archive()

                # 압축 엔진 모듈의 unarc 멤버 함수 호출
                for inst in self.kavmain_inst:
                    try:
                        unpack_data = inst.unarc(arc_engine_id, arc_name, name_in_arc)

                        if unpack_data:
                            # 압축을 해제하여 임시 파일을 생성
                            rname = self.temp_path.mktemp()
                            fp = open(rname, 'wb')
                            fp.write(unpack_data)
                            fp.close()

                            rname_struct = file_struct
                            rname_struct.set_filename(rname)
                            break
                    except AttributeError:
                        continue

                return rname_struct
        except IOError:
            pass

        return None

    # ---------------------------------------------------------------------
    # arclist(self, file_struct, fileformat)
    # 플러그인 엔진에게 압축 파일의 내부 리스트를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    #         format      - 미리 분석한 파일 포맷 분석 정보
    # 리턴값 : [압축 파일 내부 리스트] or []
    # ---------------------------------------------------------------------
    def arclist(self, file_struct, fileformat):
        arc_list = [] #압축파일 목록
        file_scan_list = []  # 검사 대상 정보를 모두 가짐 (k2file.FileStruct)

        rname = file_struct.get_filename()
        deep_name = file_struct.get_additional_filename()
        mname = file_struct.get_master_filename()
        level = file_struct.get_level()

        # 압축 엔진 모듈의 arclist 멤버 함수 호출
        for inst in self.kavmain_inst:
            try:
                if self.options['opt_arc']:
                    arc_list = inst.arclist(rname, fileformat)

                if len(arc_list):
                    for alist in arc_list:
                        arc_id = alist[0]
                        name = alist[1]

                        if len(deep_name):
                            dname = dname = '%s/%s' % (deep_name, name)
                        else:
                            dname = '%s' % name

                        fs = k2file.FileStruct()
                        fs.set_archive(arc_id, rname, name, dname, mname, False, False, level + 1)
                        file_scan_list.append(fs)

                    self.result['Packed'] += 1

                    break
            except AttributeError:
                continue

        return file_scan_list

    # ---------------------------------------------------------------------
    # format(self, file_struct)
    # 플러그인 엔진에게 파일 포맷 분석을 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    # 리턴값 : {파일 포맷 분석 정보} or {}
    # ---------------------------------------------------------------------
    def format(self, file_struct):
        ret = {}
        filename = file_struct.get_filename()

        fp = None
        mm = None

        try:
            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            # 엔진 모듈의 format 멤버 함수 호출
            for inst in self.kavmain_inst:
                try:
                    ff = inst.format(mm, filename)
                    if ff:
                        ret.update(ff)
                except AttributeError:
                    pass

            mm.close()
            fp.close()
        except IOError:
            pass


        return ret

    def __update_arc_file_struct(self, p_file_info):
        # 실제 압축 파일 이름이 같은 파일을 모두 추출한다.
        t = []
        arc_level = p_file_info.get_level()

        while len(self.update_info):
            if self.update_info[-1].get_level() == arc_level:
                t.append(self.update_info.pop())
            else:
                break
        t.reverse()

        ret_file_info = self.update_info.pop()

        b_update = False

        for finfo in t:
            if finfo.is_modify():
                b_update = True
                break

        if b_update:
            arc_name = t[0].get_archive_filename()
            arc_engine_id = t[0].get_archive_engine_name()

            for inst in self.kavmain_inst:
                try:
                    ret = inst.mkarc(arc_engine_id, arc_name, t)
                    if ret:
                        break

                except AttributeError:
                    continue

                ret_file_info.set_modify(True)  # 수정 여부 표시

            #압축된 파일들 모두 삭제
            for tmp in t:
                t_fname = tmp.get_filename()
                #플러그인 엔진에 의해 파일이 치료되었을 수 있음
                if os.path.exists(t_fname):
                    os.remove(t_fname)

        return ret_file_info




