DISALLOWED_CHARA_DICT = str.maketrans("", "", r'<>{}:;\'"')
def filter_input(input):
    """ Checks if input contains any disallowed characters and removes them """
    if isinstance(input, str):
        filteredinput = input.translate(DISALLOWED_CHARA_DICT)
        return filteredinput
