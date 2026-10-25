"""Two-VM OT forensics exercise; safe software-only Modbus/TCP at 10.20.30.10:1502."""
import datetime as dt
import json
import socket
import struct
import sys

IP, PORT, REGISTER = '10.20.30.10', 1502, 16


def read_n(s, n):
    result = b''
    while len(result) < n:
        part = s.recv(n - len(result))
        if not part:
            raise EOFError('connection closed')
        result += part
    return result


def exchange(s, pdu):
    s.sendall(struct.pack('>HHHB', 1, 0, len(pdu) + 1, 1) + pdu)
    header = read_n(s, 7)
    tid, protocol, size, unit = struct.unpack('>HHHB', header)
    response = read_n(s, size - 1)
    if tid != 1 or protocol != 0 or unit != 1 or response[0] & 0x80:
        raise ValueError(f'Invalid/exception response: {response.hex()}')
    return response


def server():
    current = 50
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((IP, PORT))
        s.listen(5)
        print(f'Simulated PLC register {REGISTER} = {current}; listening at {IP}:{PORT}', flush=True)
        while True:
            connection, client = s.accept()
            with connection:
                try:
                    head = read_n(connection, 7)
                    tid, protocol, size, unit = struct.unpack('>HHHB', head)
                    if protocol != 0 or not 2 <= size <= 254:
                        continue
                    pdu = read_n(connection, size - 1)
                    func, addr, arg = struct.unpack('>BHH', pdu)
                    before = current
                    if func == 3 and addr == REGISTER and arg == 1:
                        response = b'\x03\x02' + struct.pack('>H', current)
                        event = 'READ'
                    elif func == 6 and addr == REGISTER and 0 <= arg <= 100:
                        current = arg
                        response = pdu
                        event = 'WRITE_APPLIED'
                    else:
                        response = bytes([func | 128, 2])
                        event = 'REJECTED'
                    connection.sendall(struct.pack('>HHHB', tid, 0, len(response) + 1, unit) + response)
                    log = dict(time_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                               client_ip=client[0], event=event, function=func,
                               register=addr, argument=arg, before=before, after=current)
                    with open('plc_audit.jsonl', 'a') as f:
                        f.write(json.dumps(log) + '\n')
                    print(json.dumps(log), flush=True)
                except (EOFError, ValueError, struct.error, OSError) as e:
                    print('Rejected malformed connection:', e, flush=True)


def client(mode, arg=None):
    pdu = struct.pack('>BHH', 3, REGISTER, 1) if mode == 'read' else struct.pack('>BHH', 6, REGISTER, arg)
    with socket.create_connection((IP, PORT), timeout=4) as s:
        answer = exchange(s, pdu)
    if mode == 'read':
        print('Register 16 =', struct.unpack('>H', answer[2:4])[0])
    else:
        print('Write acknowledged:', arg)


if __name__ == '__main__':
    if sys.argv[1:] == ['server']:
        server()
    elif sys.argv[1:] == ['read']:
        client('read')
    elif len(sys.argv) == 3 and sys.argv[1] == 'write' and sys.argv[2] == '90':
        client('write', 90)
    else:
        raise SystemExit('Usage: python3 quick_lab.py server | read | write 90')
