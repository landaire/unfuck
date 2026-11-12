RESULT = (
    'abc'.isalpha(), 'ab1'.isalpha(), ''.isalpha(), '\xe9'.isalpha(),
    '123'.isdigit(), '12a'.isdigit(), ''.isdigit(),
    'ab12'.isalnum(), 'ab 12'.isalnum(), ''.isalnum(),
    ' \t\n\r\x0b\x0c'.isspace(), ' a'.isspace(), ''.isspace(), '\x1c'.isspace(),
    u'\xe9\u0101'.isalpha(), u'\u0663\u0664'.isdigit(), u'\u0663'.isdecimal(), u'\xb2'.isdigit(), u'\xb2'.isdecimal(),
    u'\xbd'.isnumeric(), u'\xbd'.isdigit(), u'\u2167'.isnumeric(), u'12'.isnumeric(), u''.isnumeric(),
    u'\x1c\x1d\x1e\x1f'.isspace(), u'\xa0\u3000\u2028'.isspace(), u'\u200b'.isspace(),
    u'a\u0663'.isalnum(), u'\u0300'.isalpha(), u'\u02b0'.isalpha(),
    hasattr('', 'isdecimal'), hasattr(u'', 'isnumeric'),
)
