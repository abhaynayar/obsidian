import subprocess

def load_file(fname):
    with open(fname,'rb') as f:
        return bytearray(f.read())

input_samples = [
        load_file('input.sample')
]

while True: #fuzzer never stop
    mutated_sample = mutate(input_samples)
