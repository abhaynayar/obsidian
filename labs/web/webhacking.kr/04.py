import hashlib
import os

for i in range(23807095,99999999+1):
    m = str(i)+'salt_for_you'
    for j in range(500):
        m = hashlib.sha1(m.encode()).hexdigest()
    print(i,m)
    if m == '258c9b35267407e0cf4c4fba6421f96dcee6af91':
        break

"""
<?php
  sleep(1); // anti brute force
  if((isset($_SESSION['chall4'])) && ($_POST['key'] == $_SESSION['chall4'])) solve(4);
  $hash = rand(10000000,99999999)."salt_for_you";
  $_SESSION['chall4'] = $hash;
  for($i=0;$i<500;$i++) $hash = sha1($hash);
?>
"""
