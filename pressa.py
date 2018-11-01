import base64
import math
import re
import sys


class Colors:
    HEADER = '-!CoLoR!-[95m'
    OKBLUE = '-!CoLoR!-[94m'
    OKGREEN = '-!CoLoR!-[92m'
    WARNING = '-!CoLoR!-[93m'
    FAIL = '-!CoLoR!-[91m'
    ENDC = '-!CoLoR!-[0m'
    BOLD = '-!CoLoR!-[1m'
    UNDERLINE = '-!CoLoR!-[4m'

    bHEADER = b'-!CoLoR!-[95m'
    bOKBLUE = b'-!CoLoR!-[94m'
    bOKGREEN = b'-!CoLoR!-[92m'
    bWARNING = b'-!CoLoR!-[93m'
    bFAIL = b'-!CoLoR!-[91m'
    bENDC = b'-!CoLoR!-[0m'
    bBOLD = b'-!CoLoR!-[1m'
    bUNDERLINE = b'-!CoLoR!-[4m'


non_printable = re.compile(r"[^\x20-\x7E]")
non_printable_b = re.compile(rb"[^\x20-\x7E]")
non_printable_replace = (Colors.FAIL + "." + Colors.ENDC).encode("ascii")


def color_range(str, start, end=None, color=Colors.bOKGREEN):
    end = end or start + 1
    return str[:start] + color + str[start:end] + Colors.bENDC + str[end:]


def replace_binary(data):
    if isinstance(data, bytes):
        data = data.replace(b"\n", Colors.bWARNING + b"N" + Colors.bENDC)
        data = non_printable_b.sub(non_printable_replace, data)
    else:
        data = data.replace("\n", Colors.WARNING + "N" + Colors.ENDC)
        data = non_printable.sub(non_printable_replace.decode("ascii"), data)
    return data


cleanup = re.compile(r"(-!CoLoR!-)|(\.)|(\[\d+m)")


def mprint(data, prefix="", suffix=""):
    if isinstance(data, bytes):
        data = data.decode("ascii")

    if not cleanup.sub("", data):
        return

    prefix = prefix.replace("-!CoLoR!-", "\033")
    suffix = suffix.replace("-!CoLoR!-", "\033")
    data = data.replace("-!CoLoR!-", "\033")

    if prefix:
        sys.stdout.write(prefix)
        sys.stdout.write(" ")

    sys.stdout.write(data)

    if suffix:
        sys.stdout.write(" ")
        sys.stdout.write(suffix)

    sys.stdout.write("\n")


best_chars = re.compile(rb"[ A-Za-z0-9]")
good_chars = re.compile(rb"[?!\-.,]")
some_chars = re.compile(rb"[#+'*\":;=]")
weights = 3, 1, 0.5


def rate(chars):
    if len(chars) == 0:
        return 0
    return (len(best_chars.findall(chars)) * weights[0] +
            len(good_chars.findall(chars)) * weights[1] +
            len(some_chars.findall(chars)) * weights[2]) / len(chars)


def collect_cars(data, pos):
    return bytes(x[pos] for x in data if len(x) > pos)


def print_results(rated_results):
    for i, rating, result in rated_results:
        result = replace_binary(result)
        prefix = replace_binary("{:-3d} ({}) S:{:.02f} -".format(i, chr(i), rating))
        mprint(result, prefix=prefix)


def monotest(data, key, cipher, pprint=True):
    results = []
    for guess in range(256):
        result = []
        for text in data:
            for char_idx in range(len(key), len(text), cipher.keylen):
                result.append(cipher.decrypt_char(text, char_idx, key + bytes([guess])))
        results.append(bytes(result))

    rated_results = []
    for i, result in enumerate(results):
        rated_results.append((i, rate(result), result))

    rated_results = sorted(rated_results, key=lambda x: x[1])

    if pprint:
        print_results(rated_results)

    return rated_results


def print_exc(e):
    mprint(" ".join([Colors.FAIL, "error", str(e), Colors.ENDC]))


print_state = False


def menu(data, rated_results, key, cipher, last_guess=b""):
    best_guesses = map(lambda x: x[0], reversed(rated_results[-10:]))
    best_guesses = ", ".join(
        ("{} (" + Colors.OKBLUE + "{}" + Colors.ENDC + ")").format(i, chr(i)) for i in best_guesses)
    best_guesses = replace_binary(best_guesses)

    global print_state
    if print_state:
        test_guess(data, key, cipher)
        print_state = False

    print()
    mprint(replace_binary(b"Current key: " + Colors.bOKBLUE + (key or b" ") + Colors.bENDC))
    mprint("Best guesses: {}".format(best_guesses))
    mprint("[" + Colors.OKBLUE + "s" + Colors.ENDC + "]ow chars, " +
           "[" + Colors.OKBLUE + "t" + Colors.ENDC + "]est guess, " +
           "[" + Colors.OKBLUE + "c" + Colors.ENDC + "]urrent state, " +
           "[" + Colors.OKBLUE + "a" + Colors.ENDC + "]ccept or {}, ".format(
        ("last guess: " + last_guess.decode("ascii")) if last_guess else "best guess") +
           "cri[" + Colors.OKBLUE + "b" + Colors.ENDC + "], " +
           "set [" + Colors.OKBLUE + "k" + Colors.ENDC + "]ey, " +
           "[" + Colors.WARNING + "e" + Colors.ENDC + "]nd")

    try:
        choice = input("Choice: ")
    except:
        choice = "e"

    if not choice:
        return menu(data, rated_results, key, cipher, last_guess)

    if len(choice) > 1 and choice[1] == " ":
        choice = choice[0] + choice[2:]
    print()
    print_current_state = False
    try:
        if choice[0] == "t":
            try:
                test_guess(data, key, cipher, bytes([int(choice[1:])]))
                last_guess = bytes([int(choice[1:])])
            except Exception as e:
                print_exc(e)

        elif choice[0] == "a":
            try:
                if len(choice) > 1:
                    return key + bytes([int(choice[1:])])
                else:
                    if last_guess:
                        return key + last_guess
                    else:
                        return key + (bytes([rated_results[-1][0]]))
            except Exception as e:
                print_exc(e)

        elif choice[0] == "s":
            print_results(rated_results)

        elif choice[0] == "c":
            test_guess(data, key, cipher)

        elif choice[0] == "k":
            return choice[1:].encode("ascii")

        elif choice[0] == "b":
            args = choice[1:]
            idx, crib = args.split(",", 1)
            print_state = True
            return key + cipher.calculate_key(data[int(idx)], len(key), crib.encode("ascii"))

        elif choice[0] == "e":
            print("Key:", key.decode("ascii"))
            exit(0)
    except Exception as e:
        print_exc(e)

    return menu(data, rated_results, key, cipher, last_guess)


def test_guess(data, key, cipher, test=b""):
    count = 0
    for i, x in enumerate(data):
        cipher_all = cipher.decrypt(x, key + test)
        for y in range(0, len(cipher_all), cipher.keylen):
            row_xor = cipher_all[y:y + len(key + test)]
            if test:
                row_xor = color_range(row_xor, len(key + test) - 1)
            row_xor = replace_binary(row_xor)
            mprint(row_xor, prefix="{:-3d} -".format(count))
            count += 1


class Cipher:
    def __init__(self, keylen):
        self.keylen = keylen

    def encrypt(self, plaintext, key):
        res = []
        for i, c in enumerate(plaintext):
            keypos = i % self.keylen
            if keypos < len(key):
                res.append(self.encrypt_char(plaintext, i, key))
            else:
                res.append(0)
        return bytes(res)

    def decrypt(self, cipher, key):
        res = []
        for i, c in enumerate(cipher):
            keypos = i % self.keylen
            if keypos < len(key):
                res.append(self.decrypt_char(cipher, i, key))
            else:
                res.append(0)
        return bytes(res)

    def encrypt_char(self, plaintext, pos, key):
        pass

    def decrypt_char(self, cipher, pos, key):
        pass

    def calculate_key(self, cipher, pos, plaintext):
        pass


class SymmetricCipher(Cipher):
    def encrypt(self, cipher, key):
        return self.decrypt(cipher, key)

    def encrypt_char(self, cipher, pos, key):
        return self.decrypt_char(cipher, pos, key)


class XORCipher(SymmetricCipher):
    def decrypt_char(self, data, pos, key):
        return data[pos] ^ key[pos % self.keylen]

    def calculate_key(self, cipher, pos, plaintext):
        return bytes(cipher[pos + i] ^ p for i, p in enumerate(plaintext))


def hex_to_bytes(str):
    return bytes.fromhex(str)


def bytes_to_base64(bytes):
    return base64.b64encode(bytes)


class Trimmer:
    """
    MODE_COLUMN:
    e.g. AAAA, BBBB, CCCC trimmed to 6 chars will be
    - AA
    - BB
    - CC
    """
    MODE_COLUMN = 0

    """
    MODE_LINE:
    e.g. AAAA, BBBB, CCCC trimmed to 6 chars will be:
    - AAAABB
    """
    MODE_LINE = 1

    @classmethod
    def _trim_line(cls, data, length):
        result = []
        for x in data:
            result.append(x[:length])
            length -= len(result[-1])
            if length <= 0:
                return result

    @classmethod
    def _trim_column(cls, data, length):
        count_per_line = int(math.ceil(length / len(data)))
        result = []
        for x in data:
            result.append(x[:count_per_line])
        return result

    @classmethod
    def trim(cls, mode, data, length):
        if mode == cls.MODE_COLUMN:
            return cls._trim_column(data, length)
        else:
            return cls._trim_line(data, length)


class PressA:
    def __init__(self, trim_mode=Trimmer.MODE_COLUMN, max_ciphertext_per_key=100):
        self.cipher = None
        self.cipher_text = b""
        self.blocks = []
        self.key = b""
        self.max_ciphertext_per_key = max_ciphertext_per_key
        self.trim_mode = trim_mode

    def trim_ciphertext(self):
        max_ciphertext_length = self.max_ciphertext_per_key * self.cipher.keylen
        self.cipher_text = self.cipher_text[:max_ciphertext_length]

    def _remove_newlines(self, text):
        return text.strip().replace(b"\n", b"").replace(b"\r", b"")

    def setCipher(self, c):
        self.cipher = c
        return self

    def read_hex_lines(self, file):
        with open(file, "rb") as f:
            self.cipher_text = [base64.b64decode(x.strip(b" \r\n")) for x in f.readlines()]
        return self

    def read_hex(self, file):
        with open(file, "rb") as f:
            self.cipher_text = [hex_to_bytes(self._remove_newlines(file.read()))]
        return self

    def read_binary(self, file):
        with open(file, "rb") as f:
            self.cipher_text = [f.read()]
        return self

    def read_base64(self, file):
        with open(file, "rb") as f:
            self.cipher_text = [base64.b64decode(self._remove_newlines(f.read()))]
        return self

    def read_base64_lines(self, file):
        with open(file, "rb") as f:
            self.cipher_text = [base64.b64decode(x.strip(b" \r\n")) for x in f.readlines()]
        return self

    def _split_blocks(self, c, bs):
        return [c[x:x + bs] for x in range(0, len(c), bs)]

    def toWin(self):
        assert self.cipher, "set a cipher first"
        self.data = Trimmer.trim(self.trim_mode, self.cipher_text, self.max_ciphertext_per_key * self.cipher.keylen)
        while True:
            rated_results = monotest(self.data, self.key, self.cipher)
            self.key = menu(self.data, rated_results, self.key, self.cipher, b"")[:self.cipher.keylen]
