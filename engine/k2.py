# -*- coding:utf-8 -*-

# -------------------------------------------------------------------------
# 실제 임포트 모듈
# -------------------------------------------------------------------------
import os
import sys
from optparse import OptionParser


from ctypes import windll, Structure, c_short, c_ushort,  byref

# -------------------------------------------------------------------------
# 주요 상수
# -------------------------------------------------------------------------
import kavcore.k2engine

g_options = None  # 옵션

KAV_VERSION = '0.01'
KAV_BUILDDATE = 'Sep 20 2021'
KAV_LASTYEAR = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

# -------------------------------------------------------------------------
# 콘솔에 색깔 출력을 위한 클래스 및 함수들
# -------------------------------------------------------------------------
#
# FOREGROUND_BLACK = 0x0000
# FOREGROUND_BLUE = 0x0001
# FOREGROUND_GREEN = 0x0002
# FOREGROUND_CYAN = 0x0003
# FOREGROUND_RED = 0x0004
# FOREGROUND_MAGENTA = 0x0005
# FOREGROUND_YELLOW = 0x0006
# FOREGROUND_GREY = 0x0007
# FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

SHORT = c_short
WORD = c_ushort


class Coord(Structure):
    _fields_ = [
    ("X", SHORT),
    ("Y", SHORT)]


class SmallRect(Structure):
    _fields_ = [
        ("Left", SHORT),
        ("Top", SHORT),
        ("Right", SHORT),
        ("Bottom", SHORT)]


class ConsoleScreenBufferInfo(Structure):
    _fields_ = [
        ("dwSize", Coord),
        ("dwCursorPosition", Coord),
        ("wAttributes", WORD),
        ("srWindow", SmallRect),
        ("dwMaximumWindowSize", Coord)]

# winbase.h
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12

stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

def get_text_attr():
    csbi = ConsoleScreenBufferInfo()
    GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
    return csbi.wAttributes


def set_text_attr(color):
    SetConsoleTextAttribute(stdout_handle, color)


def cprint(msg, color):
    default_colors = get_text_attr()
    default_bg = default_colors & 0x00F0

    set_text_attr(color | default_bg)
    sys.stdout.write(msg)
    set_text_attr(default_colors)

    sys.stdout.flush()

def print_error(msg):
    #cprint('Error: ', FOREGROUND_RED|FOREGROUND_INTENSITY)
    print(msg)

def getch():
    if os.name == 'nt':
        import msvcrt

        return msvcrt.getch()
    else:
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch

def convert_display_filename(real_filename):
    # 출력용 이름
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    display_filename = unicode(real_filename, fsencoding).encode('cp949') #서버상 오류 발생하여 소스 코드 수정
    return display_filename

def display_line(filename, message):
    filename += ' '
    filename = convert_display_filename(filename)
    len_fname = len(filename)
    len_msg = len(message)

    if len_fname + 1 + len_msg < 79:
        fname = '%s' % filename
    else:
        able_size = 79 - len_msg
        able_size -= 5  # ...
        min_size = able_size / 2
        if able_size % 2 == 0:
            fname1 = filename[:min_size-1]
        else:
            fname1 = filename[:min_size]
        fname2 = filename[len_fname - min_size:]

        fname = '%s ... %s' % (fname1, fname2)

    print(fname + ' ')
    print(message + '\n')

# -------------------------------------------------------------------------
# print_k2logo()
# 백신 로고를 출력한다
# -------------------------------------------------------------------------
def print_k2logo():
    logo = '''CloudBread Anti-Virus I (for %s) Ver %s (%s)
Copyright (C) 2021-%s CloudBread. All rights reserved.
'''

    print('------------------------------------------------------------')
    s = logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    print(s)
    print('------------------------------------------------------------')


# 파이썬의 옵션 파서 정의 (에러문 제어)
class OptionParsingError(RuntimeError):
    def __init__(self, msg):
        self.msg = msg

class OptionParsingExit(Exception):
    def __init__(self, status, msg):
        self.msg = msg
        self.status = status

class ModifiedOptionParser(OptionParser):
    def error(self, msg):
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None):
        raise OptionParsingExit(status, msg)

# -------------------------------------------------------------------------
# define_options()
# 백신의 옵션을 정의한다
# -------------------------------------------------------------------------
def define_options():
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files",
                      action="store_true", dest="opt_files",
                      default=True)
    parser.add_option("-r", "--arc",
                      action="store_true", dest="opt_arc",
                      default=False)
    parser.add_option("-I", "--list",
                      action="store_true", dest="opt_list",
                      default=False)
    parser.add_option("-V", "--vlist",
                      action="store_true", dest="opt_vlist",
                      default=False)
    parser.add_option("-p", "--prompt",
                      action="store_true", dest="opt_prompt",
                      default=False)
    parser.add_option("-d", "--dis",
                      action="store_true", dest="opt_dis",
                      default=False)
    parser.add_option("-l", "--del",
                      action="store_true", dest="opt_del",
                      default=False)
    parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)

    return parser
# -------------------------------------------------------------------------
# scan의 콜백 함수
# -------------------------------------------------------------------------
def scan_callback(ret_value):

    global g_options

    fs = ret_value['file_struct']

    if len(fs.get_additional_filename()) != 0:
        disp_name = '%s (%s)' % (fs.get_master_filename(), fs.get_additional_filename())
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if ret_value['result']:
        state = 'infected'

        vname = ret_value['virus_name']
        message = '%s : %s' %(state, vname)
        #message_color = FOREGROUND_RED |FOREGROUND_INTENSITY
    else:
        message = 'ok'
        #message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(disp_name, message)

    if g_options.opt_prompt:
        while True and ret_value['result']:
            print('Disinfect/Delete/Ignore/Quit? (d/l/i/q) : ')
            ch = getch().lower()
            print(ch)

            if ch == 'd':
                return kavcore.k2const.K2_ACTION_DISINFECT
            elif ch == 'l':
                return kavcore.k2const.K2_ACTION_DELETE
            elif ch == 'i':
                return kavcore.k2const.K2_ACTION_IGNORE
            elif ch == 'q':
                return kavcore.k2const.K2_ACTION_QUIT
    elif g_options.opt_dis:  # 치료 옵션
        return kavcore.k2const.K2_ACTION_DISINFECT
    elif g_options.opt_del:  # 삭제 옵션
        return kavcore.k2const.K2_ACTION_DELETE

    return kavcore.k2const.K2_ACTION_IGNORE





# -------------------------------------------------------------------------
# print_options()
# 백신의 옵션을 출력한다
# -------------------------------------------------------------------------
def print_options():
    options_string = '''Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -I,  --list            display all files
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
        -?,  --help            this help
                               * = default option'''

    print(options_string)

# -------------------------------------------------------------------------
# disinfect의 콜백 함수
# -------------------------------------------------------------------------
def disinfect_callback(ret_value, action_type):
    fs = ret_value['file_struct']
    message = ''

    if len(fs.get_additional_filename()) != 0:
        disp_name = '%s (%s)' % (fs.get_master_filename(), fs.get_additional_filename())
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if fs.is_modify():  # 수정 성공?
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfected'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deleted'

        #message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfection failed'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deletion failed'

         #message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(disp_name, message)

# -------------------------------------------------------------------------
# update의 콜백 함수
# -------------------------------------------------------------------------
def update_callback(ret_file_info):

    if ret_file_info.is_modify():  # 수정되었다면 결과 출력
        disp_name = ret_file_info.get_filename()

        message = 'updated'
        #message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY

        display_line(disp_name, message)

# -------------------------------------------------------------------------
# listvirus의 콜백 함수
# -------------------------------------------------------------------------
def listvirus_callback(plugin_name, vnames) :
    for vname in vnames:\
        print('%-50s [%s.kmd]' %(vname, plugin_name))

# -------------------------------------------------------------------------
# print_result(result)
# 악성코드 검사 결과를 출력한다.
# 입력값 : result - 악성코드 검사 결과
# -------------------------------------------------------------------------
def print_result(result):

    print('Results:\n')
    print('Folders           :%d\n' % result['Folders'])
    print('Files             :%d\n' % result['Files'])
    #cprint('Packed            :%d\n' % result['Packed'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    print('Infected files    :%d\n' % result['Infected_files'])
    print('Identified viruses:%d\n' % result['Identified_viruses'])
    print('I/O errors        :%d\n' % result['IO_errors'])

def print_usage():
    print('\nUsage: k2.py path[s] [options]')

def parser_options():
    parser = define_options()  # 백신 옵션 정의

    if len(sys.argv) < 2:
        return 'NONE_OPTION', None
    else:
        try:
            (options, args) = parser.parse_args()
            if len(args) == 0:
                return options, None
        except OptionParsingError as e:  # 잘못된 옵션 사용일 경우
            # print 'ERROR'
            return 'ILLEGAL_OPTION', e.msg
        except OptionParsingExit as e:
            return 'ILLEGAL_OPTION', e.msg

        return options, args

# -------------------------------------------------------------------------
# main()
# -------------------------------------------------------------------------
def main():
    global g_options
    options, args = parser_options()
    g_options = options  # 글로벌 options 셋팅
    print_k2logo()
    # 잘못된 옵션인가?
    if options == 'NONE_OPTION':  # 옵션이 없는 경우
        print_usage()
        print_options()
        return 0
    elif options == 'ILLEGAL_OPTION':  # 정의되지 않은 옵션을 사용한 경우
        print_usage()
        print('Error: %s' % args)  # 에러 메시지가 담겨 있음
        return 0

    # Help 옵션을 사용한 경우 또는 인자 값이 없는 경우
    if options.opt_help:
        print_usage()
        print_options()
        return 0

    # 백신 엔진 구동
    k2 = kavcore.k2engine.Engine()

    if not k2.set_plugins('plugins'): # 플로그인 엔진 설정
        print_error('CloudBread AntiVirus Engine set_plugins')
        return 0

    kav = k2.create_instance() # 백신 엔진 인스턴스 생성

    if not kav:
        print_error('CloudBread AntiVirus Engine create_instance')
        return 0

    if not kav.init(): #  전체 플러그인 엔진 초기화화
        print
        print_error('CloudBread AntiVirus Engine init')
        return 0

    # 엔진 버전을 출력
    c = kav.get_version()
    msg = '\rLast updated %s UTC\n' % c.ctime()
    print(msg)

    # 진단/치료 가능한 악성코드 수 출력
    msg = 'Signature number: %d\n\n' %kav.get_signum()
    print(msg)

    kav.set_options(options) # 옵션을 설정

    if options.opt_vlist is True: # 악성코드 목록 출력
        kav.listvirus(listvirus_callback)
    else:
        if args:
            # 검사용 path 설정
            kav.set_result()
            for scan_path in args: # 옵션을 제외한 첫번째가 검사대상
                scan_path=os.path.abspath(scan_path)

                if os.path.exists(scan_path): # 폴더 혹은 파일이 존재하는가?
                    kav.scan(scan_path, scan_callback)
                else:
                    print_error('Invalid path: \'%s\'' % scan_path)
            ret = kav.get_result()
            print_result(ret)


    kav.uninit()

if __name__=='__main__':
    main()