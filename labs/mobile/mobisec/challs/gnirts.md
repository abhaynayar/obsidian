## gnirts

In the main activity, we come across the following code

```
if (FlagChecker.checkFlag(MainActivity.this, flagWidget.getText().toString()))
	msg = "Valid flag!";
```

In checkFlag(flag) we have:

```
if (!flag.startsWith("MOBISEC{") || !flag.endsWith("}"))
	return false;
```

FLAG = "MOBISEC{}"

```
String core = flag.substring(8, 40);
if (core.length() != 32)
	return false;
```

FLAG = "MOBISEC{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}"

```
String[] ps = core.split(foo());
if (ps.length != 5 || !bim(ps[0]) || !bum(ps[2]) || !bam(ps[4])	|| !core.replaceAll("[A-Z]", "X").replaceAll("[a-z]", "x").replaceAll("[0-9]", " ").matches("[A-Za-z0-9]+.7spaces.[A-Za-z0-9]+.[Xx ]+.[A-Za-z0-9 ]+"))
	return false;
```

```
public static String foo() {
    String s = "Vm0wd2QyVkZNVWRYV0docFVtMVNWVmx0ZEhkVlZscDBUVlpPVmsxWGVIbFdiVFZyVm0xS1IyTkliRmRXTTFKTVZsVmFWMVpWTVVWaGVqQTk=";
    for (int i = 0; i < 10; i++) {
        s = new String(Base64.decode(s, 0));
    }
    return s;
}
```

From cyber-chef I decoded the given string 10 times go get the character "-".

FLAG = "MOBISEC{AAAAA-AAAAAAAAAAAAAAAAAAAAAAAAAA}"

```
private static boolean bim(String s) {
	// entire string should be lowercase
	return s.matches("^[a-z]+$");
}
```

FLAG = "MOBISEC{aAaAa-AAAAAAAAAAAAAAAAAAAAAAAAAA}"

According to the regex condition:

FLAG = "MOBISEC{xXxXx-0123456-XXx01-XXxx-XXxx01 }"

```
char[] syms = new char[4];
int[] idxs = {13, 21, 27, 32};

Set<Character> chars = new HashSet<>();

for (int i = 0; i < syms.length; i++) {
    syms[i] = flag.charAt(idxs[i]);
    chars.add(Character.valueOf(syms[i]));
}
```

```syms``` is essentially taking all the characters positioned according to ```idxs``` in ```flag```.

Each character is inserted as it is into the set ```chars```.

FLAG = "MOBISEC{xXxXx-0123456-XXx01-XXxx-XXxx01 }"

Therefore, chars = {'-','-','-','-'}.

```
int sum = 0;

for (char c : syms)
    sum += c;
```

Then it calculates the sum of ASCII values of all characters in ```syms```.

```
>>> ord('-')\*4
180
```

It matches with the conditions ahead. Also size is 1, since there are no duplicates in ```chars```.

```
if (sum == 180 && chars.size() == 1
	&& me(ctx, dh(gs(ctx.getString(R.string.ct1), ctx.getString(R.string.k1)), ps[0]), ctx.getString(R.string.t1))
	&& me(ctx, dh(gs(ctx.getString(R.string.ct2), ctx.getString(R.string.k2)), ps[1]), ctx.getString(R.string.t2))
	&& me(ctx, dh(gs(ctx.getString(R.string.ct3), ctx.getString(R.string.k3)), ps[2]), ctx.getString(R.string.t3))
	&& me(ctx, dh(gs(ctx.getString(R.string.ct4), ctx.getString(R.string.k4)), ps[3]), ctx.getString(R.string.t4))
	&& me(ctx, dh(gs(ctx.getString(R.string.ct5), ctx.getString(R.string.k5)), ps[4]), ctx.getString(R.string.t5))
	&& me(ctx, dh(gs(ctx.getString(R.string.ct6), ctx.getString(R.string.k6)), flag), ctx.getString(R.string.t6)))
    return true;
```

The outermost function that we have to check is ```me```.

```
private static boolean me(Context ctx, String s1, String s2) {
    try {
        return ((Boolean) s1.getClass().getMethod(r(ctx.getString(R.string.m1)), new Class[]{Object.class}).invoke(s1, new Object[]{s2})).booleanValue();
    } catch (Exception e) {
        Log.e("MOBISEC", "Exception: " + Log.getStackTraceString(e));
        return false;
    }
}
```

```me``` calls ```r``` and gets reverse of the string that was called.

```
public static String r(String s) {
    return new StringBuffer(s).reverse().toString();
}
```

In the first case it is ```R.string.m1``` which turns out to be "equals". This means that me is checking if the two strings passed as parameters are equal of not.

```
<string name="m1">slauqe</string>
```

The next function we have to look at is ```dh```. It takes two strings as parameters and hashes the second string with the algorithm mentioned in the first string.

```
private static String dh(String hash, String s) {
    try {
        MessageDigest md = MessageDigest.getInstance(hash);
        md.update(s.getBytes());
        return toHexString(md.digest());
    } catch (Exception e) {
        return null;
    }
}
```

For each of the hashing algorithms depicted by string names starting with ct and k, ```gs``` function is applied.

```
<string name="ct1">xwe</string>
<string name="ct2">asd</string>
<string name="ct3">uyt</string>
<string name="ct4">42s</string>
<string name="ct5">p0X</string>
<string name="ct6">70 IJTR</string>

<string name="k1">53P</string>
<string name="k2">,7Q</string>
<string name="k3">8=A</string>
<string name="k4">yvF</string>
<string name="k5">=tm</string>
<string name="k6">dxa</string>
```

```
private static String gs(String a, String b) {
    String s = BuildConfig.FLAVOR;
    for (int i = 0; i < a.length(); i++) {
        s = s + Character.toString((char) (a.charAt(i) ^ b.charAt(i % b.length())));
    }
    return s;
}
```

Using a simple python script, we can decipher the algorithms:

```
>>> a = "xwe"
>>> b = "53P"
>>> for i,j in zip(a,b):
...     print(chr(ord(i)^ord(j))),
... 
M D 5
```

The results are as follows:
- k1,k2,k3,k4,k5 = "MD5"
- k6 = "SHA-256"

```
if (sum == 180 && chars.size() == 1
	&& me(ctx, dh("MD5", ps[0]), ctx.getString(R.string.t1))
	&& me(ctx, dh("MD5", ps[1]), ctx.getString(R.string.t2))
	&& me(ctx, dh("MD5", ps[2]), ctx.getString(R.string.t3))
	&& me(ctx, dh("MD5", ps[3]), ctx.getString(R.string.t4))
	&& me(ctx, dh("MD5", ps[4]), ctx.getString(R.string.t5))
	&& me(ctx, dh("SHA-256", flag), ctx.getString(R.string.t6)))
    return true;
```

```
<string name="t1">6e9a4d130a9b316e9201238844dd5124</string>
<string name="t2">7c51a5e6ea3214af970a86df89793b19</string>
<string name="t3">e5f20324ae520a11a86c7602e29ecbb8</string>
<string name="t4">1885eca5a40bc32d5e1bca61fcd308a5</string>
<string name="t5">da5062d64347e5e020c5419cebd149a2</string>
<string name="t6">1c4d1410a4071880411f02ff46370e46b464ab2f87e8a487a09e13040d64e396</string>
```

Using crackstation.net, we can crack the MD5 hashes.

```
6e9a4d130a9b316e9201238844dd5124	md5	peppa
7c51a5e6ea3214af970a86df89793b19	md5	9876543
e5f20324ae520a11a86c7602e29ecbb8	md5	BAAAM
1885eca5a40bc32d5e1bca61fcd308a5	md5	A1z9
da5062d64347e5e020c5419cebd149a2	md5	3133337
```

And we get the flag: ```MOBISEC{peppa-9876543-BAAAM-A1z9-3133337}```

