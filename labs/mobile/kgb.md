# KGB Messenger solutions
https://github.com/tlamb96/kgb_messenger

## First Flag

_MainActivity.java_

When we first open the app we see that it says only runs on Russian devices.

Looking at the decompilation, we see we need to change some property.

```
String property = System.getProperty("user.home");
if (property == null || property.isEmpty() || !property.equals("Russia"))
    a("Integrity Error", "This app can only run on Russian devices.");
```

Also the user name should be in the whitelist.

```
if (str == null || str.isEmpty() || !str.equals(getResources().getString(R.string.User)))
    a("Integrity Error", "Must be on the user whitelist.");
```

If we go look at User in resources, we find:

```<string name="User">RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==</string>```

The base64 decoded version of that string is: `FLAG{57ERL1NG_4RCH3R}`

## Second Flag

_LoginActivity.java_

<string name="username">codenameduchess</string>
<string name="password">84e343a0486ff05530df6c705c8bb4</string>

search hash on google: "goodjob" (not working), but "guest" works.

```
class second {

    static String n = "codenameduchess";
    static String o = "guest"; 

    public static void main(String args[]) {

        char[] cArr = {'(', 'W', 'D', ')', 'T', 'P', ':', '#', '?', 'T'};
        cArr[0] = (char) (cArr[0] ^ n.charAt(1));
        cArr[1] = (char) (cArr[1] ^ o.charAt(0));
        cArr[2] = (char) (cArr[2] ^ o.charAt(4));
        cArr[3] = (char) (cArr[3] ^ n.charAt(4));
        cArr[4] = (char) (cArr[4] ^ n.charAt(7));
        cArr[5] = (char) (cArr[5] ^ n.charAt(0));
        cArr[6] = (char) (cArr[6] ^ o.charAt(2));
        cArr[7] = (char) (cArr[7] ^ o.charAt(3));
        cArr[8] = (char) (cArr[8] ^ n.charAt(6));
        cArr[9] = (char) (cArr[9] ^ n.charAt(8));
        System.out.println("FLAG{" + new String(cArr) + "}");

    }   
}
```

The second flag is `FLAG{G00G13_PR0}`


## Third Flag

_MessengerActivity.java_

There were several things that needed to be reversed. I first decompiled the activity using jadx, and then reversed the code.


```
public class Third {

	static String p = "V@]EAASB\u0012WZF\u0012e,a$7(&am2(3.\u0003";
	static String r = "\u0000dslp}oQ\u0000 dks$|M\u0000h +AYQg\u0000P*!M$gQ\u0000";

	private static String a(String str) {
        
		char[] charArray = str.toCharArray();
        
		for (int i = 0; i < charArray.length / 2; i++) {
            char c = charArray[i];
            charArray[i] = (char) (charArray[(charArray.length - i) - 1] ^ 'A');
            charArray[(charArray.length - i) - 1] = (char) (c ^ '2');
        }
        
		return new String(charArray);
    }

	private static String b(String str) {
		
		char[] charArray = str.toCharArray();

        for (int i2 = 0; i2 < charArray.length / 2; i2++) {
            char c = charArray[i2];
            charArray[i2] = charArray[(charArray.length - i2) - 1];
            charArray[(charArray.length - i2) - 1] = c;
        }

		for (int k=0; k<charArray.length; k++) {

			if(k%8==0){
				System.out.print("?");
				continue;	
			}

			int flag = 0;
			
			for (int j=0; j<=255; ++j) {

				if( charArray[k] == (char) (  (char)j ^ ((char)j >> (k%8))  )) {
					System.out.print((char) j);
					flag = 1;
					break;
				}

			}
			
			if(flag == 0) System.out.print(".");

		}
        
        return new String(charArray);
    }

	private static String i(String q, String s) {
        if (q == null || s == null) {
            return "Nice try but you're not that slick!";
        }
        char[] charArray = q.substring(19).toCharArray();
        charArray[1] = (char) (charArray[1] ^ 'U');
        charArray[2] = (char) (charArray[2] ^ 'F');
        charArray[3] = (char) (charArray[3] ^ 'F');
        charArray[5] = (char) (charArray[5] ^ '_');
        char[] charArray2 = s.substring(7, 13).toCharArray();
        charArray2[1] = (char) (charArray2[1] ^ '}');
        charArray2[2] = (char) (charArray2[2] ^ 'v');
        charArray2[3] = (char) (charArray2[3] ^ 'u');
        return new String(charArray) + "_" + new String(charArray2);
    }

	public static void main(String args[]) {

		String one = a(p);
		String two = "May I *PLEASE* have the password?"; // b(r): "?ay I *P?EASE* h?ve the ?assword?"

		System.out.println(i(one,two));

	}

}
```

The first method could easily be reversed, but the second method was irreversible due to an XOR that resulted in no trace of the original data being left. Therefore as you can see, I have put it up against 256 standard ASCII characters. Despite the brute force, there were letters that were completely obliterated due to an XOR with themselves (when i=0).

You can see the message with the i%8 characters replaced with question marks.

The final flag is `FLAG{p455w0rd_P134SE}`

