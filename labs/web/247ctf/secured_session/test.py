def secret_key_to_int(s):
    try:
        secret_key = int(s)
    except ValueError:
        secret_key = 0
    return secret_key

i1 = input()
secret_key = secret_key_to_int(i1)
print(secret_key)
