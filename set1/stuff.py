from statistics import mean

x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

y1 = "1c0111001f010100061a024b53535009181c"
y2 = "686974207468652062756c6c277320657965"

hex_encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def hex_to_b64(s):
    return s.decode("hex").encode("base64")

def hex_xor(s1, s2):
    return hex(int(s1, 16) ^ int(s2, 16))

def char_score(c):
    char_freq = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33,
        'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41,
        'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98,
        'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07, ' ': 6.00
    }
    if c in char_freq:
        return char_freq[c]
    else:
        return 0

def plaintext_score(s):
    return mean(list(map(char_score, s.upper())))

def decode_single_byte_xor(cipher: bytearray):
    max_score = 0;
    english_plaintext = ''
    for key in bytearray(range(256)):
        plaintext = bytearray()

        for c in cipher:
            plaintext.append(c ^ key)

        score = plaintext_score(plaintext.decode('cp437'))

        if score > max_score:
            max_score = score
            english_plaintext = plaintext.decode('cp437')

    return (english_plaintext, max_score)

def find_single_byte_encrypted_xor(ciphers):
    lis = list(map(decode_single_byte_xor, ciphers))
    return max(lis, key=lambda item:item[1])

with open('set1ch4.txt') as f:
    hex_encoded_list = f.read()

x = list(map(bytearray.fromhex, hex_encoded_list.split('\n')))

print(find_single_byte_encrypted_xor(x))
