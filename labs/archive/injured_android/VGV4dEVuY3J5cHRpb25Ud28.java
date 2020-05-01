import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import java.util.Base64;

public class VGV4dEVuY3J5cHRpb25Ud28 {

    private static final byte[] KEY = Hide.getKey();

	public static void main(String args[]) {
		decrypt("k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ==");
	}

    public static String decrypt(String value) {
        if (isBase64(value)) {
            try {
                SecretKey key = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(KEY));
                byte[] encrypedPwdBytes = Base64.getDecoder().decode(value);
                Cipher cipher = Cipher.getInstance("DES");
                cipher.init(2, key);
                String decrypedText = new String(cipher.doFinal(encrypedPwdBytes));
                System.out.println("Decrypted: " + value + " -> " + decrypedText);
                return decrypedText;
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Not a string!");
            return value;
        }

		return null;
    }


    public static boolean isBase64(String value) {
        try {
            Base64.getDecoder().decode(value);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

class Hide {
    private static byte[] encKey = Base64.getDecoder().decode("Q2FwdHVyM1RoMXM=");
    private static byte[] encKeyTwo = Base64.getDecoder().decode("e0NhcHR1cjNUaDFzVG9vfQ==");
    private static String remoteUrl = "9EEADi^^:?;FC652?5C@:5]7:C632D6:@]4@>^DB=:E6];D@?";

    static byte[] getKey() {
        return encKey;
    }

    static byte[] getAnotherKey() {
        return encKeyTwo;
    }

    static String getRemoteUrl() {
        return remoteUrl;
    }
}

