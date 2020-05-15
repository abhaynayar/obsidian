<?php
$ip = '103.41.24.37';
for($i=0;$i<=strlen($ip);$i++) $ip=str_replace($i,ord($i),$ip);
$ip=str_replace(".","",$ip);
$ip=substr($ip,0,10);
$answer = $ip*2;
$answer = $ip/2;
$answer = str_replace(".","",$answer);
print("answerip/{$answer}_{$ip}.php");
?>

