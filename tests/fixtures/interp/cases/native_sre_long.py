import re

text = 'ab' * 20000 + 'c'
RESULT = [
    re.match(r'(a|b)*c', text).span(), re.match(r'(?:ab)*?c', text).span(), re.search(r'(a|b)*?d', 'ab' * 300),
    re.match(r'(.)*', text).group(1), len(re.findall(r'a', text)), re.match(r'((a)|(b))*c', text).groups(),
    re.sub(r'(a)(b)', r'\2\1', text)[-5:], len(re.split(r'b', text)), re.match(r'(?:a|b)+?c', text).end(),
]
