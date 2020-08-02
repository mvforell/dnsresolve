import socket

from select import select
from struct import pack, unpack
from sys import argv, exit
from random import randint

def make_header(msg_id, qdcount=1, opcode='query', recursion=False):
    '''
    returns a header (as a bytes object) for a dns query with specified id, query count and opcode
    (valid opcodes are query, iquery and status), using recursion if wanted
    '''
    qr = 0 # query message

    opcode = opcode.lower()
    if opcode == 'query':
        opcode = 0
    elif opcode == 'iquery':
        opcode = 1
    else: # opcode == 'status'
        opcode = 2

    tc = 0 # no truncation
    rd = 1 if recursion else 0
    line_two = (qr << 15) + (opcode << 11) + (tc << 9) + (rd << 8)

    return pack('!HHHHHH',
                msg_id,
                line_two,
                qdcount,
                0, # no answers
                0, # no name servers
                0) # no additional records

def make_qname(domain):
    '''
    returns a dns qname for the given domain (can't handle message compression)
    '''
    qname = b''
    for label in domain.split('.'):
        l = pack('!B', len(label))
        qname += l + label.encode()
    return qname + b'\x00'

def make_request(domain, operation='query', recursive=False):
    '''
    constructs a dns query request for the given domain
    '''
    msg_id = randint(0, 2**16 - 1)
    qname = make_qname(domain)
    qtype = 1 # A record
    qclass = 1 # IN class

    header = make_header(msg_id, opcode=operation, recursion=recursive)
    question = qname + pack('!HH', qtype, qclass)

    return header + question

def parse_header(header):
    '''
    parses a dns header and returns a dict containing the different parts as keys with their
    corresponding set values in the header
    '''
    msg_id, line_two, qcount, ancount, nscount, arcount = unpack('!HHHHHH', header)
    qr = (line_two & (1 << 15)) >> 15
    opcode = (line_two & (0b1111 << 11)) >> 11
    aa = (line_two & (1 << 10)) >> 10
    tc = (line_two & (1 << 9)) >> 9
    rd = (line_two & (1 << 8)) >> 8
    ra = (line_two & (1 << 7)) >> 7
    rcode = line_two & 0b1111
    return {'msg_id': msg_id, 'qr': qr, 'opcode': opcode, 'aa': aa, 'tc': tc, 'rd': rd,
            'ra': ra, 'rcode': rcode, 'qcount': qcount, 'ancount': ancount,
            'nscount': nscount, 'arcount': arcount}

def parse_qname(qname):
    '''
    parses a dns qname and returns it in common url format plus the length of the qname
    '''
    domain = ''
    i = 0
    c = qname[0]
    while c != 0:
        domain += qname[i + 1:i + c + 1].decode()
        i += c + 1
        c = qname[i]
        if c != 0:
            domain += '.'
    return (domain, i + 1) # count the last null byte

def parse_question(res, qcount):
    '''
    parses the question section of a dns request (res must not include the header of the request)
    and returns a tuple of a list of parsed questions and the length of the question section
    '''
    questions = []
    c = 0
    for i in range(qcount):
        domain, l = parse_qname(res[c:])
        c += l
        qtype, qclass = unpack('!HH', res[c:c + 4])
        c += 4
        questions.append({'qname': domain, 'qtype': qtype, 'qclass': qclass})
    return (questions, c)

def parse_answer(res, ancount):
    '''
    parses the answer section of a dns request (res must not include the header or question section
    of the request) and returns a tuple of a list of parsed answers and the length of the answer
    section
    '''
    answers = []
    c = 0
    for i in range(ancount):
        domain, l = parse_qname(res[c:])
        c += l
        atype, aclass, ttl, rdlength = unpack('!HHIH', res[c:c + 10])
        c += 10
        rdata = res[c:c + rdlength]
        c += rdlength

        if atype == 1 and aclass == 1:
            rdata = '.'.join([str(b) for b in rdata])

        answers.append({'name': domain, 'type': atype, 'class': aclass, 'ttl': ttl,
            'rdlength': rdlength, 'rdata': rdata})
    return answers

def parse_message(res):
    '''
    parses a dns message (only header, question and answer section) and returns the parsed
    values as a dict
    '''
    header = res[:12]
    parsed_header = parse_header(header)

    if parsed_header['rcode'] == 1:
        raise ValueError('Format error - The name server was unable to interpret the query.')
    elif parsed_header['rcode'] == 2:
        raise ValueError('Server failure - The name server was unable to process this query ' \
                + 'due to a problem with the name server.')
    elif parsed_header['rcode'] == 3:
        raise ValueError('Name Error - Meaningful only for responses from an authoritative ' \
                + 'name server, this code signifies that the domain name referenced in the ' \
                + 'query does not exist.')
    elif parsed_header['rcode'] == 4:
        raise ValueError('Not Implemented - The name server does not support the requested ' \
                + 'kind of query.')
    elif parsed_header['rcode'] == 5:
        raise ValueError('Refused - The name server refuses to perform the specified operation ' \
                + 'for policy reasons. For example, a name server may not wish to provide the ' \
                + 'information to the particular requester, or a name server may not wish to ' \
                + 'perform a particular operation (e.g., zone transfer) for particular data.')

    parsed_question, qlength = parse_question(res[12:], parsed_header['qcount'])
    parsed_answer = parse_answer(res[12 + qlength:], parsed_header['ancount'])
    return {'header': parsed_header, 'questions': parsed_question, 'answers': parsed_answer}

def print_help():
    print(f'USAGE: {argv[0]} url [nameserver] [timeout in seconds]')

def main():
    # TODO: implement message compression support
    if (len(argv) > 4):
        print_help()
        exit(1)
    if len(argv) == 2 and (argv[1] == '-h' or argv[1] == '--help'):
        print_help()
        exit(0)

    NS = argv[2] if len(argv) == 3 else '1.1.1.1'
    try:
        TIMEOUT = int(argv[3]) if len(argv) == 4 else 1
    except ValueError:
        print_help()
        exit(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # DNS via UDP because we're oldschool
    s.setblocking(0)
    domain = argv[1] if len(argv) in (2, 3, 4) else 'duckduckgo.de'
    msg = make_request(domain, recursive=True)
    s.sendto(msg, (NS, 53))

    ready = select([s], [], [], TIMEOUT)
    if ready[0]:
        res = s.recv(512)
        try:
            parsed = parse_message(res)
        except ValueError as e:
            print(str(e))
            exit(1)
        answer = parsed['answers'][0]
        print(f"IPv4 address for {domain}: {answer['rdata']} (TTL: {answer['ttl']}, reported by {NS})")
    else:
        print('Timed out.')
        exit(1)

if __name__ == '__main__':
    main()
