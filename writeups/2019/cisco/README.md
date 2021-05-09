<h2>Autograph - Cisco SecCon CTF</h2>
<p>30/09/2019</p>

<p>
I scored a total of 3000 points out of 4100 in the Cisco SecCon CTF 2019.
There were a lot of interesting problems. Here, I am going to write about
a web challenge called Autograph.
</p>

<p>
The first thing we see on the website is a registration form. There is a
script in the source code to package all the information and send it as
XML. There is also a comment <b>&lt;!-- EVERYONE EXCEPT "ADMIN" CAN REGISTER FOR THE EVENT  !--&gt;</b>.
</p>

<p>
After reading the comment, I tried putting in the name field's value as
admin and realized that in order to get back the email's value reflected to
the webpage, we require the name field to have the value admin. For ANY
value of email it reflects back the email (saying that it already exists).
</p>
<p>
I tried entering the form on the webpage with some random values and
intercepted the request through Burp. After seeing the XML in the request
body, I thought of trying out an
<a href="https://portswigger.net/web-security/xxe">XXE</a> payload.
</p>

<pre>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ELEMENT foo ANY&gt;
  &lt;!ENTITY bar SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;root&gt;
	&lt;name&gt;admin&lt;/name&gt;
	&lt;email&gt;&amp;bar;&lt;/email&gt;
&lt;/root&gt;
</pre>

<p>
The payload worked, as the <b>/etc/passwd</b> contents were returned.
Now we can browse around the server and see what all things there are.
After scratching my head for a while, I remembered that the XML data is
being submitted to process.php (the same file the XML data is posted to).
</p>

<p>
I thought of viewing this file on the server but when I tried to view it,
I got the result of the php file executing and not the actual source code.
In order to see the source code of the file, I used 
<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#php-wrapper-inside-xxe">php://filter</a>
to convert it into base64 and then got the contents reflected into the
response.
</p>

<pre>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ELEMENT foo ANY&gt;
  &lt;!ENTITY bar SYSTEM "php://filter/convert.base64-encode/resource=process.php"&gt;
]&gt;
&lt;root&gt;
	&lt;name&gt;admin&lt;/name&gt;
	&lt;email&gt;&bar;&lt;/email&gt;
&lt;/root&gt;
</pre>

<p>
After getting the base64 encoded string, I decoded it and saw the contents
of the process.php file. The first line contained an include to another
file.  Using the same technique as before, I got the source of the newly
found file. 
</p>

<p>
Flag: <b>SecConCTF{HEY_I_THOUGHT_XML_WAS_SAFE:(}</b>
</p>
