import hashlib

word_freq = {
    "bracket": 20442,
    "anchor": 40694,
    "colleagu": 61801,
    "margin": 81562,
    "personnel": 103834,
    "enjoy": 121693,
    "musician": 143236,
    "color": 162901,
    "geographi": 184573,
    "angel": 203727,
}

USE_LESS_DATA = True

if USE_LESS_DATA:
    for _k in word_freq.keys():
        word_freq[_k] = word_freq[_k] // 10

with open("sse-data-large", "w") as f:
    f.write(str(len(word_freq.keys())) + "\n")
    for _k in word_freq.keys():
        f.write(_k + "\n")
        f.write(str(word_freq[_k]) + "\n")
        for i in range(word_freq[_k]):
            f.write(hashlib.sha256(
                (_k+str(i)).encode()).hexdigest()[:10] + "\n")
