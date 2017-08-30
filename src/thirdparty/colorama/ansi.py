# Copyright Jonathan Hartley 2013. BSD 3-Clause license, see LICENSE file.
'''
This module generates ANSI character codes to printing colors to terminals.
See: http://en.wikipedia.org/wiki/ANSI_escape_code
'''

from src.utils import colors

CSI = '\033['
OSC = '\033]'
BEL = '\007'


def code_to_chars(code):
    return CSI + str(code) + 'm'


class AnsiCodes(object):
    def __init__(self, codes):
        for name in dir(codes):
            if not name.startswith('_'):
                value = getattr(codes, name)
                setattr(self, name, code_to_chars(value))


class AnsiCursor(object):
    def UP(self, n=1):
        return CSI + str(n) + "A"
    def DOWN(self, n=1):
        return CSI + str(n) + "B"
    def FORWARD(self, n=1):
        return CSI + str(n) + "C"
    def BACK(self, n=1):
        return CSI + str(n) + "D"
    def POS(self, x=1, y=1):
        return CSI + str(y) + ";" + str(x) + "H"

def set_title(title):
    return OSC + "2;" + title + BEL

def clear_screen(mode=2):
    return CSI + str(mode) + "J"

def clear_line(mode=2):
    return CSI + str(mode) + "K"


class AnsiFore:
    if colors.ENABLE_COLORING:
        BLACK           = 30
        RED             = 31
        GREY            = 90
        GREEN           = 32
        YELLOW          = 33
        BLUE            = 34
        MAGENTA         = 35
        CYAN            = 36
        WHITE           = 37
        RESET           = 39

        # These are fairly well supported, but not part of the standard.
        LIGHTBLACK_EX   = 90
        LIGHTRED_EX     = 91
        LIGHTGREEN_EX   = 92
        LIGHTYELLOW_EX  = 93
        LIGHTBLUE_EX    = 94
        LIGHTMAGENTA_EX = 95
        LIGHTCYAN_EX    = 96
        LIGHTWHITE_EX   = 97
    else:
        BLACK = RED = GREY = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = 0

        # These are fairly well supported, but not part of the standard.
        LIGHTBLACK_EX = LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = LIGHTWHITE_EX = 0


class AnsiBack:
    if colors.ENABLE_COLORING:
        BLACK           = 40
        RED             = 41
        GREEN           = 42
        YELLOW          = 43
        BLUE            = 44
        MAGENTA         = 45
        CYAN            = 46
        WHITE           = 47
        RESET           = 49

        # These are fairly well supported, but not part of the standard.
        LIGHTBLACK_EX   = 100
        LIGHTRED_EX     = 101
        LIGHTGREEN_EX   = 102
        LIGHTYELLOW_EX  = 103
        LIGHTBLUE_EX    = 104
        LIGHTMAGENTA_EX = 105
        LIGHTCYAN_EX    = 106
        LIGHTWHITE_EX   = 107
    else:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = 0

        # These are fairly well supported, but not part of the standard.
        LIGHTBLACK_EX = LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = LIGHTWHITE_EX = 0      


class AnsiStyle:
    if colors.ENABLE_COLORING:
        BRIGHT    = 1
        DIM       = 2
        UNDERLINE = 4
        NORMAL    = 22
        RESET_ALL = 0
    else:
        BRIGHT = DIM = UNDERLINE = NORMAL = RESET_ALL = 0

Fore = AnsiCodes( AnsiFore )
Back = AnsiCodes( AnsiBack )
Style = AnsiCodes( AnsiStyle )
Cursor = AnsiCursor()
