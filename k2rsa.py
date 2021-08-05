#-*-coding:utf-8 -*-

import base64
import marshal
import random

'''
---------------------------------------------------------------------------
# 확장 유클리드 호제법 알고리즘
# 점수 m,n의 최대공약수를 gcd(m,n)와 나타낼 때, 확장된 윸ㄹ리드 호제법을 이용하여, 
# am+bn = gcd(m,n)의 해가 되는 정수 a,b 짝을 착아낸다.

# __ext_euclid(a,b)
# 인자값 : a,b - 정수
# 리턴값 : d, x, y - 유클리드 호제법 해
---------------------------------------------------------------------------
'''
def __ext_euclid(a,b):
    i = -1
    list_r = list()
    list_q = list()
    list_x = list()
    list_y = list()

    i +=1
    list_r.append(a) # -1
    list_r.append(b) # 0

    list_q.append(0)  # -1
    list_q.append(0)  # 0

    list_x.append(1)  # -1
    list_x.append(0)  # 0

    list_y.append(0)  # -1
    list_y.append(1)  # 0

    i = 2
    while 1:
        list_r.append(list_r[i - 2] % list_r[i - 1])
        list_q.append(list_r[i - 2] / list_r[i - 1])

        if list_r[i] == 0 :
            d = list_r[i-1]
            x = list_x[i-1]
            y = list_y[i-1]

            if x < 0 :
                x += b
            if y < 0 :
                y += b

            return d, x, y

        list_x.append(list_x[i - 2] - (list_q[i] * list_x[i - 1]))
        list_y.append(list_y[i - 2] - (list_q[i] * list_y[i - 1]))

        i += 1


'''
---------------------------------------------------------------------------
# Simple RSA Algotithm
# __mr(n)
# 주어진 숫자가 소수일 가능성을 체크한다.

# 인자값 : n - 숫자
# 리턴값 : 0 - 소수 아님, 1-> 소수
---------------------------------------------------------------------------
'''
def __mr(n) :
    composite = 0
    inconclusive = 0

    def get_kq(num) :
        sub_k = 0

        sub_t = num - 1
        b_t = bin(sub_t)

        for sub_i in range(len(b_t) -1, -1, -1) :
            if b_t[sub_i] == '0' :
                sub_k += 1
            else :
                break

        sub_q = sub_t >> sub_k
        return  sub_k, sub_q

    k,q = get_kq(n)

    if k ==0 :
        return 0 # 소수 아님
    for i in range (10) :
        a = int(random.uniform(2,n)) # 1<a<n
        if pow(a,q,n)==1:
            inconclusive +=1
            continue

        t= 0
        for j in range(k):
            if pow(a,(2*j*q),n) == n -1 :
                inconclusive +=1
                t =1

        if t ==0:
            composite += 1

    if inconclusive >= 6 : # 통계적으로 계산에 의해 60%이상이면 소수로 인정
        return 1

'''
---------------------------------------------------------------------------
# __gen_number(gen_bit)
# 주어진 bit 수에 해당하는 하나의 홀수를 생성한다.

# 인자값 : gen_bit - 생성한 홀수의 bit 수
# 리턴값 : 홀수
---------------------------------------------------------------------------
'''
def __gen_number(gen_bit) :
    random.seed()

    b= ''
    for i in range(gen_bit - 1) :
        b+=str(int(random.uniform(1,10))%2)
    b += '1' # 마지막 bit에 1을 추가하여 홀수를 만든다.
    return int(b,2)

'''
---------------------------------------------------------------------------
# __gen_prime(gen_bit)
# 주어진 bit 수에 해당하는 하나의 소수를 생성한다.

# 인자값 : gen_bit - 생성한 소수의 bit 수
# 리턴값 : 소수
---------------------------------------------------------------------------
'''
def __gen_prime(gen_bit):
    while 1 :
        p = __gen_number(gen_bit)
        if __mr(p) == 1:
            return p

'''
---------------------------------------------------------------------------
# __gen_ed (n)
# n보다 작고, n과 서로소인 정수 e를 찾는다.
# 확장 유클리드 호제법을 이용해서 d * e / n 으로 나눴을때 나머지가 1인
# 정수 d를 찾는다.
# 인자값 : n - 정수
# 리턴값 : e,d
---------------------------------------------------------------------------
'''
def __get_ed (n):
    while 1:
        t = int(random.uniform(2,1000))
        d,x,y = __ext_euclid(t,n)
        if d ==1 :
            return t,x
'''
---------------------------------------------------------------------------
# __value_to_string(val)
# 숫자를 문자열로 변환한다.

# 인자값 : val - 숫자
# 리턴값 : 문자열
---------------------------------------------------------------------------
'''
def __value_to_string(val):
    ret=''
    for i in range(32):
        b = val & 0xff
        val >>= 8
        ret +=chr(b)
        
        if val == 0 :
            break
    return ret
'''
---------------------------------------------------------------------------
# __string_to_value(buf)
# 암호화를 쉽게 하기 위해 문자열을 숫자로 바꾼다.

# 인자값 : buf - 문자열
# 리턴값 : 숫자
---------------------------------------------------------------------------
'''
def __string_to_value(buf):
    plantext_ord = 0
    for i in range(len(buf)):
        plantext_ord |=ord(buf[i]) << (i*8)
    return plantext_ord

'''
---------------------------------------------------------------------------
# create_key(pu_fname='key.prk', pr_fname='key.skr',debug)
# rsa 키를 생성한다.

# 인자값 : pu_fname- 공개키, pr_fname-개인키
# 리턴값 : 키 생성 성공 여부
---------------------------------------------------------------------------
'''
def create_key(pu_fname='key.prk', pr_fname='key.skr',debug=False):
    p = __gen_prime(128)
    q = __gen_prime(128)

    # print 'p
    # print 'q

    n = p * q
    # print 'n

    qn = (p -1) * (q - 1)

    #print 'Q(n)

    e = __get_ed(qn)
    d = __get_ed(qn)
    # print 'e
    # print 'd

    pu = [e, n]
    pr = [d, n]

    # print 'pu
    # print 'pr

    # 공개키와 개인키를 base64로 구성한다.
    pu_data: str= base64.b64encode(marshal.dumps(pu))
    pr_data: str= base64.b64encode(marshal.dumps(pr))

    try: # 공개키와 개인키를 파일로 만든다.
        open(pu_fname, 'wt').write(pu_data)
        open(pr_fname, 'wt').write(pr_data)
    except IOError :
        return False

    # 공개키와 개인키가 생성되었다.
    if debug:
        print('[*] Make key : %s, %s' %(pu_fname, pr_fname))

    return True

'''
---------------------------------------------------------------------------
# read_key(key_filename)
# 주어진 key 파일을 읽어 rsa 키로 변환한다.

# 인자값 : key_filename - rsa 키 파일
# 리턴값 : rsa 키
---------------------------------------------------------------------------
'''
def read_key(key_filename):
    try:
        with open(key_filename, 'rt') as fp :
            b = fp.read()
            s = base64.b64decode(b)
            key = marshal.loads(s)

        return key
    except IOError:
        return None
'''
---------------------------------------------------------------------------
# crypt(buf, key)
# 주어진 버퍼와 rsa 키를 이용해서 양/복호화를 한다.

# 인자값 : buf - 양/복화화 대상 버퍼
          key - rsa키 
# 리턴값 : 양복호화된 결과물
---------------------------------------------------------------------------
'''
def crypt(buf, key):
    plantext_ord = __string_to_value(buf)

    # 주어진 키로 양/복호화
    val = pow(plantext_ord,key[0],key[1])

    return __value_to_string(val)