# https://www.hidglobal.com/sites/default/files/resource_files/6090-905_f.1_-_pivclass_fips-201_reader_operation_and_output_selections.pdf
# Table 2.
encoding = {
        "0":  "00001",
        "1":  "10000",
        "2":  "01000",
        "3":  "11001",
        "4":  "00100",
        "5":  "10101",
        "6":  "01101",
        "7":  "11100",
        "8":  "00010",
        "9":  "10011",
        "S":  "11010",
        "F":  "10110",
        "E":  "11111",
        " ":  "",
        }


fascn_test = "S 1341 F 0001 F 987654 F 1 F 1 F 1234567890 1 1341 1 E"
fascn =      "S 9999 F 9999 F 999999 F 0 F 1 F 0000000000 3 1337 2 E"

def encode(fascn):
    lrc = 0
    res = ""
    for c in fascn:
        enc = encoding[c]
        res += enc + ""
        if enc:
            lrc ^= int(enc[:4], 2)
    
    b = (1 + bin(lrc).count('1')) % 2
    return int(res + f"{lrc:04b}" + str(b), 2)  


assert encode(fascn_test) == int("D4324858210C2D3171B525A1685A08C92ADE0A6184324843E2", 16)
print(f"{encode(fascn):X}")
