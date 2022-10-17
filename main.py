import time
import hashlib
import multiprocessing


alphabet = "abcdefghijklmnopqrstuvwxyz"
password_len = 5
sha256_hashes = ["1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
          "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
          "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f"]

def generate_password(alphabet, password_len, num):
    password = ""
    for i in range(password_len):
        password += alphabet[num % len(alphabet)]
        num = num // len(alphabet)
    return password[::-1]

def bruteforce_sha256(id_thread, hashes, first_pass, end_pass):
    for i in range(first_pass, end_pass):
        password = generate_password(alphabet, password_len, i)
        sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if sha256_hash in hashes:
            print("[*] Поток {} : подобран пароль {} для хеша {}".format(id_thread, password, sha256_hash))

def bruteforce_hash(hashes, alphabet_len, password_len):
    print("[*] Кол-во хэшей {}. Длина пароля: {}".format(len(hashes), password_len))
    count_password = alphabet_len**password_len-1
    count_threads = int(input("[*] Введите кол-во потоков. Максимум потоков - {} ".format(multiprocessing.cpu_count())))
    start_time = time.perf_counter()
    if count_threads < 1: count_threads = 1
    count_password_thread = count_password // count_threads
    threads = []
    start = 0
    for id in range(count_threads):
        thr = multiprocessing.Process(target=bruteforce_sha256, args=(id, hashes, start, start+count_password_thread if id != count_threads-1 else count_password))
        thr.start()
        start += count_password_thread
    for thread in threads:
        thread.join()
    print("[*] Время выполнения {}".format(time.perf_counter() - start_time))

if __name__ == "__main__":
    bruteforce_hash(sha256_hashes, len(alphabet), password_len)