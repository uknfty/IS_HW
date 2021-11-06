import socket
import threading
import time
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import pyDH


# 서버 연결정보; 자체 서버 실행시 변경 가능
SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

METHOD = ['CONNECT', 'DISCONNECT', 'KEYXCHG', 'KEYXCHGRST', 'MSGSEND']
HEADERS = ['Algo:', 'Credential:', 'Timestamp:', 'Nonce:', 'From:', 'To:']
Block_Size = 16

global Key_Waiting
Key_Waiting = 0  # 키 교환 상태 분기용
global USER
USER = ''  # 자신의 Credential
global dh1  # Diffie-Hellman
global shared_key_dic
shared_key_dic = {}  # 교환된 키 저장
global iv_dic
iv_dic = {}  # 교환된 iv 저장


def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)

        if len(readbuff) == 0:
            continue

        recv_payload = readbuff.decode('utf-8')
        parse_payload(recv_payload)


def socket_send():

    global USER
    global Key_Waiting
    global dh1
    global shared_key_dic
    global iv_dic

    while True:
        time.sleep(1)  # 연속 입력 방지용
        print('\n------- MESSAGE CREATING -------')
        s = input("PREAMBLE: 3EPROTO ")
        if s not in METHOD:
            while s not in METHOD:
                print('Wrong METHOD')
                s = input("PREAMBLE: 3EPROTO ")
        msg = '3EPROTO ' + s + '\n'

        # 서버에 연결하기, 서버와의 연결 해제하기
        if s in ['CONNECT', 'DISCONNECT']:
            s = input('Credential: ')
            USER = s
            msg = msg + 'Credential: ' + s + '\n'

        # 키 교환 (먼저 키교환 요청을 보내게 되는 상황)

        # aes 키 생성에 필요한 키를 Diffie-Hellman을 사용하여 공유한다.

        # Diffie-Hellman 공유키를 생성하여 상대에게 보내면
        # 상대에게서 다시 공유키를 전달 받는다.

        # 키 교환 요청을 보내면 다시 'KEYXCHG'를 통해 Diffie-Hellman에 필요한
        # 공유키를 전달받게 된다.

        # parse_payload()의 먼저 키 교환 요청을 했을 때 상황으로 가서
        # Diffie-Hellman 키 공유를 하게 된다.
        if s in ['KEYXCHG', 'KEYXCHGRST']:
            # algo = input('Algo(AES-256-CBC, Diffie-Hellman): ')
            # msg = msg + 'Algo: ' + algo + '\n'
            print('Algo: AES-256-CBC, Diffie-Hellman')
            msg = msg + 'Algo: AES-256-CBC, Diffie-Hellman' + '\n'
            print('From: ' + USER)
            msg = msg + 'From: ' + USER + '\n'
            s = input('To: ')
            msg = msg + 'To: ' + s + '\n\n'

            # key = get_random_bytes(32)
            # key = base64.b64encode(key).decode('utf-8')
            # aes의 key
            # Diffie-Hellman으로 공유하기 때문에
            # aes의 랜덤한 key 생성은 사용하지 않음.

            # aes의 iv를 핸덤하게 생성
            iv = get_random_bytes(16)
            # iv_dic[s] = iv
            iv_base64 = base64.b64encode(iv).decode('utf-8')
            # Diffie-Hellman의 공유키 생성
            dh1 = pyDH.DiffieHellman()
            dh1_pubkey = dh1.gen_public_key()

            msg = msg + str(dh1_pubkey) + '\n'
            msg = msg + str(iv_base64) + '\n'

            Key_Waiting = 1
        
        # 메세지 교환
        # shared_key 로 암호화, base64로 인코딩 후 전송
        if s in ['MSGSEND']:
            print('From: ' + USER)
            msg = msg + 'From: ' + USER + '\n'
            s = input('To: ')
            if s not in shared_key_dic:
                while s not in shared_key_dic:
                    print('Wrong user')
                    s = input('To: ')
            msg = msg + 'To: ' + s + '\n\n'

            shared_key = shared_key_dic[s]
            iv = iv_dic[s]

            body = input('MSG: ')
            body = body.encode('utf-8')

            aes = AES.new(shared_key, AES.MODE_CBC, iv)
            body = aes.encrypt(pad(body, 16))
            body = base64.b64encode(body).decode('utf-8')
            msg = msg + body + '\n'

        print('\n------- MESSAGE CREATED -------')
        print(msg)
        print('-------- MESSAGE SEND --------\n')  # 보낸 메세지 확인용
        send_bytes = msg.encode('utf-8')

        connectSocket.sendall(send_bytes)


def parse_payload(payload):

    global USER
    global Key_Waiting
    global dh1
    global shared_key_dic
    global iv_dic

    # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
    print('\n-------- MESSAGE RECEIVING --------')
    print(payload)
    print('-------- MESSAGE RECEIVED --------\n')  # 서버로부터 받은 메세지 확인용

    payload = payload.split('\n')
    # print(payload)   # payload 확인용

    # 키 교환
    if payload[0].split(' ', 2)[1] in ['KEYXCHG', 'KEYXCHGRST']:
        # 먼저 키 교환 요청을 하지 않았을 때
        # 상대가 키 교환 요청을 해온 상황이다.
        # 상대의 Diffie-Hellman 공유키를 전달받고
        # 자신의 Diffie-Hellman 공유키를 생성하여 보낸다.
        if Key_Waiting == 0:
            # print('Key_waiting 0') # 상태 확인용
            if payload[0].split(' ', 2)[1] == 'KEYXCHG' and \
                    payload[2].split(':', 2)[1] in shared_key_dic:
                msg = '3EPROTO KEYXCHGFAIL\n' + \
                      'Algo: AES-256-CBC, Diffie-Hellman\n' + \
                      'From: ' + USER + '\n' + \
                      'To: ' + payload[2].split(':', 2)[1]
                print('\n------- MESSAGE CREATED -------')
                print(msg)
                print('-------- MESSAGE SEND --------\n')  # 보낸 메세지 확인용
                send_bytes = msg.encode('utf-8')

                connectSocket.sendall(send_bytes)

            else:
                dh2 = pyDH.DiffieHellman()
                dh2_pubkey = dh2.gen_public_key()

                shared_key = dh2.gen_shared_key(int(payload[6]))
                shared_key = shared_key[:32].encode('utf-8')
                shared_key_dic[payload[2].split(':', 2)[1]] = shared_key
                # print('shared_key: ')
                # print(shared_key)  # shared_key 확인용
                iv = payload[7].encode('utf-8')
                iv = base64.b64decode(iv)
                iv_dic[payload[2].split(':', 2)[1]] = iv

                # print('shared_key_dic :', shared_key_dic)
                # print('iv_dic :', iv_dic)  # 키 확인용

                msg = '3EPROTO KEYXCHG\n' + \
                    'Algo: AES-256-CBC, Diffie-Hellman\n' + \
                    'From: ' + USER + '\n' + \
                    'To: ' + payload[2].split(':', 2)[1] + '\n\n' + \
                    str(dh2_pubkey) + '\n' + \
                    payload[7]

                print('\n------- MESSAGE CREATED -------')
                print(msg)
                print('-------- MESSAGE SEND --------\n')  # 보낸 메세지 확인용
                send_bytes = msg.encode('utf-8')

                connectSocket.sendall(send_bytes)

        # 먼저 키 교환 요청을 했을 때
        # 상대가 Diffie-Hellman 공유키를 받고 공유키를 새로생성하여 보낸상황이다.
        # 공유키를 이용하여 aes에 사용할 shared_key 를 만들면 키 교환이 끝난다.
        if Key_Waiting == 1:
            # print('Key_waiting 1') # 상태 확인용
            shared_key = dh1.gen_shared_key(int(payload[6]))
            shared_key = shared_key[:32].encode('utf-8')
            # print('shared_key: ')
            # print(shared_key)  # shared_key 확인용
            shared_key_dic[payload[2].split(':', 2)[1]] = shared_key

            iv = payload[7].encode('utf-8')
            iv = base64.b64decode(iv)
            iv_dic[payload[2].split(':', 2)[1]] = iv

            # print('shared_key_dic :', shared_key_dic)
            # print('iv_dic :', iv_dic)  # 키 확인용

            Key_Waiting = 0

    # 메세지 교환
    if payload[0].split(' ', 2)[1] in ['MSGRECV']:
        # if payload[2].split(':', 2)[1] not in shared_key_dic:
        #
        #     x = 1

        shared_key = shared_key_dic[payload[2].split(':', 2)[1]]
        iv = iv_dic[payload[2].split(':', 2)[1]]
        # print('shared_key_dic :', shared_key_dic)
        # print('iv_dic :', iv_dic)  # 키 확인용

        aes = AES.new(shared_key, AES.MODE_CBC, iv)
        recv_msg = payload[5].encode('utf-8')
        recv_msg = base64.b64decode(recv_msg)
        recv_msg = unpad(aes.decrypt(recv_msg), 16)
        recv_msg = recv_msg.decode('utf-8')
        # print(recv_msg)  # decrypt 본문 확인용
        
        dec_payload = payload[0] + '\n' + \
            payload[1] + '\n' + \
            payload[2] + '\n' + \
            payload[3] + '\n' + \
            payload[4] + '\n' + \
            recv_msg

        print('\n-------- MESSAGE RECEIVING (DECRYPT) --------')
        print(dec_payload)
        print('-------- MESSAGE RECEIVED (DECRYPT) --------\n')
        # decrypted 메세지 확인용

    # 연결 종료 (DISCONNECT)
    if payload[0].split(' ', 2)[1] in ['BYE']:
        # 초기화
        USER = ''
        shared_key_dic = {}
        iv_dic = {}

    print('\n------- MESSAGE CREATING -------')
    print("PREAMBLE: 3EPROTO ", end='')
    pass


reading_thread = threading.Thread(target=socket_read)
sending_thread = threading.Thread(target=socket_send)

reading_thread.start()
sending_thread.start()

reading_thread.join()
sending_thread.join()

# 사용방법
# PREAMBLE: 3EPROTO 가 뜨면 METHOD 입력
# 이후 각 HEADERS에 따라 내용 입력
# MSG: 헤더는 MSGSEND의 본문에 해당하는 내용 입력
#
# CONNECT로 연결 후 KEYXCHG로 상대와 키 교환
# 키 교환 이후 MSGSEND를 통해 상대와 채팅 가능

