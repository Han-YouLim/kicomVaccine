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
KAV_VERSION = '0.27'
KAV_BUILDDATE = 'Sep 20 2021'
KAV_LASTYEAR = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

# -------------------------------------------------------------------------
# 콘솔에 색깔 출력을 위한 클래스 및 함수들
# -------------------------------------------------------------------------

FOREGROUND_BLACK = 0x0000
FOREGROUND_BLUE = 0x0001
FOREGROUND_GREEN = 0x0002
FOREGROUND_CYAN = 0x0003
FOREGROUND_RED = 0x0004
FOREGROUND_MAGENTA = 0x0005
FOREGROUND_YELLOW = 0x0006
FOREGROUND_GREY = 0x0007
FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

from ctypes import windll, Structure, c_short, c_ushort, byref

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

# -------------------------------------------------------------------------
# print_k2logo()
# 백신 로고를 출력한다
# -------------------------------------------------------------------------
def print_k2logo():
    logo = '''KICOM Anti-Virus II (for %s) Ver %s (%s)
Copyright (C) 1995-%s Kei Choi. All rights reserved.
'''

    print '------------------------------------------------------------'
    s = logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    cprint(s, FOREGROUND_CYAN | FOREGROUND_INTENSITY)
    print '------------------------------------------------------------'

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
    parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)

    # 숨겨진 기능 (인공지능 AI을 위해 만든 옵션)

    parser.add_option("", "--feature",
                      type="int", dest="opt_feature",
                      default=0xffffffff)

    return parser

# -------------------------------------------------------------------------
# scan의 콜백 함수
# -------------------------------------------------------------------------
def scan_callback(ret_value):

    fs = ret_value['file_struct']

    if len(fs.get_additional_filename()) != 0:
        disp_name = '%s (%s)' % (fs.get_master_filename(), fs.get_additional_filename())
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if ret_value['result']:
        state = 'infected'

        vname = ret_value['virus_name']
        message = '%s : %s' %(state, vname)
        message_color = FOREGROUND_RED |FOREGROUND_INTENSITY
    else:
        message = 'ok'
        message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)

    if g_options.opt_prompt:
        while True and ret_value['result']: # 악성코드가 발견되었나?
            cprint('Disinfect/Delete/Ignore/Quit? (d/l/i/q) : ', FOREGROUND_CYAN | FOREGROUND_INTENSITY)
            ch = getch().lower()
            print ch

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
        -?,  --help            this help
                               * = default option'''

    print options_string

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

        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfection failed'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deletion failed'

        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)

# -------------------------------------------------------------------------
# update의 콜백 함수
# -------------------------------------------------------------------------
def update_callback(ret_file_info):

    if ret_file_info.is_modify():  # 수정되었다면 결과 출력
        disp_name = ret_file_info.get_filename()


        message = 'updated'
        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY


        display_line(disp_name, message, message_color)



# -------------------------------------------------------------------------
# print_result(result)
# 악성코드 검사 결과를 출력한다.
# 입력값 : result - 악성코드 검사 결과
# -------------------------------------------------------------------------
def print_result(result):

    print
    print

    cprint('Results:\n', FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Folders           :%d\n' % result['Folders'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Files             :%d\n' % result['Files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Packed            :%d\n' % result['Packed'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Infected files    :%d\n' % result['Infected_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Identified viruses:%d\n' % result['Identified_viruses'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('I/O errors        :%d\n' % result['IO_errors'], FOREGROUND_GREY | FOREGROUND_INTENSITY)

    print



# -------------------------------------------------------------------------
# main()
# -------------------------------------------------------------------------
def main():
    print_k2logo()

if __name__=='__main__':
    main()
