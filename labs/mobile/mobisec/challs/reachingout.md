# reachingout

> There is an HTTP server listening on 10.0.2.2:31337 (reachable from within the emulator where your app is running). The flag is there. It's easy, but you may need to pro-up your math skills.

First when we try to access the given server we get:

```
MOBISEC: You can get the flag <a href="http://10.0.2.2:31337/flag">here</a>.
```

When we follow the given link, we get a form.

```html
How much is 3 + 6?
<form action="/flag" method="POST">
  <label for="answer">Insert Answer</label>
  <input id="answer" name="answer" required type="text" value="">
  <input id="val1" name="val1" type="hidden" value="3">
  <input id="oper" name="oper" type="hidden" value="+">
  <input id="val2" name="val2" type="hidden" value="6">
  <input type="submit" value="Get Flag">
</form>
```

So in order to get the flag we need to conjure up an HTTP POST request with the required POST variables. Here is the Java code I used, and as usual make sure to have the INTERNET permission in the manifest.

```java
import ...

public class MainActivity extends AppCompatActivity {

    private static String sUrl = "http://10.0.2.2:31337/flag";

    public static String getFlag(String urlParameters) throws Exception {

        int postDataLength = urlParameters.getBytes(StandardCharsets.UTF_8).length;
        HttpURLConnection conn = (HttpURLConnection) new URL(sUrl).openConnection();

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        conn.setUseCaches(false);

        OutputStream out = new PrintStream(conn.getOutputStream());
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, "UTF-8"));
        writer.write(urlParameters);
        writer.flush();
        writer.close();
        out.close();

        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String content = "";

        while (true) {
            String readLine = rd.readLine();
            String line = readLine;
            if (readLine == null)
                return content;
            content = content + line + "\n";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        try {
            Log.e("MOBISEC", "getFlag(): " + getFlag("answer=9&val1=3&oper=%2B&val2=6"));
        } catch (Exception e) {
            Log.e("MOBISEC", "error: " + e.toString());
        }

    }
}
```

MOBISEC : getFlag(): Correct! Here is the flag: ```MOBISEC{I_was_told_by_liars_that_http_queries_were_easy}```

