import binascii as b

data = '\x00\x01\x7f\x80\xfe\xff hello\n'
qp_text = 'a b\t\n.\n' + 'x' * 80 + '='

RESULT = (
    b.hexlify(data), b.b2a_hex('\x01\xab'), b.unhexlify('ABcd01'), b.a2b_hex(u'ff00'),
    b.b2a_base64(''), b.b2a_base64('a'), b.b2a_base64('ab'), b.b2a_base64('abc'), b.b2a_base64(data),
    b.a2b_base64('YWJj'), b.a2b_base64('Y=WJj'), b.a2b_base64('YQ=='), b.a2b_base64('YQ=a='),
    b.a2b_base64('Y W\nJ j\xff'), b.a2b_base64(''), b.a2b_base64(b.b2a_base64(data)),
    b.b2a_uu(''), b.b2a_uu('x'), b.b2a_uu(data), b.a2b_uu(b.b2a_uu(data)), b.a2b_uu(''), b.a2b_uu('!80  \n'),
    b.a2b_qp('a=3Db=\nc_d=\r\ne==f=4', header=True), b.a2b_qp('a_b=4a=zz='),
    b.b2a_qp(qp_text, quotetabs=1), b.b2a_qp('a \r\nb', istext=0), b.b2a_qp('a b \r\nc\t\r\n', header=1),
    b.b2a_qp(data), b.b2a_qp('.'), b.b2a_qp('y' * 200),
    b.a2b_hqx('ABC:'), b.b2a_hqx('hi'), b.b2a_hqx(data), b.a2b_hqx(b.b2a_hqx('hey') + ':'),
    b.rlecode_hqx('aaaaaa\x90b' + 'c' * 300), b.rledecode_hqx('a\x90\x05\x90\x00'), b.rledecode_hqx(''),
    b.rledecode_hqx('\x90\x00z'),
    b.crc32('hello'), b.crc32('hello', 5), b.crc32('', -1), b.crc32(data, 2 ** 40 + 3), b.crc32(u'abc'),
    b.crc_hqx('hello', 0), b.crc_hqx('', -5), b.crc_hqx('a', -5), b.crc_hqx(data, 0x1234),
)
