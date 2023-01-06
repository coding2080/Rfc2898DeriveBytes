import module.Rfc2898DeriveBytes;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Rfc2898DeriveBytesTest {

    @Test
    public void _1() throws Exception {
        String password = "tngh7420";
        String expectedHashedText = "ADQIUxloFWtfOrHt7cI4Htnb1YfhvK/sNxZW+TJ4W21uXLbWvk2RPI0o6GqUQTC9aw==";

        String result = hashPassword(password);

        Assertions.assertEquals(expectedHashedText, result);
                Assertions.assertTrue(
                        verifyHashedPassword(
                                "AAAAAAAAAAAAAAAAAAAAAADLyFOfWWFVZaW39SMsfYYozagEhcGEg26iiNgcJz5BKg==",
                                "tngh7420")
                );

    }

    public static String hashPassword(String password) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] salt;
        byte[] buffer2;
        if (password == null)
            throw new IllegalArgumentException("password");
        Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, new byte[0x10], 0x3e8);
        salt = bytes.getSalt();
        buffer2 = bytes.getBytes(0x20);
        byte[] dst = new byte[0x31];
        System.arraycopy(salt, 0, dst, 1, 0x10);
        System.arraycopy(buffer2, 0, dst, 0x11, 0x20);
        return Base64.encodeBase64String(dst);
    }

    public static boolean verifyHashedPassword(String hashedPassword, String password) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] buffer4;
        if (hashedPassword == null)
            return false;
        if (password == null)
            throw new IllegalArgumentException("password");
        byte[] src = Base64.decodeBase64(hashedPassword);
        if ((src.length != 0x31) || (src[0] != 0))
            return false;
        byte[] dst = new byte[0x10];
        System.arraycopy(src, 1, dst, 0, 0x10);
        byte[] buffer3 = new byte[0x20];
        System.arraycopy(src, 0x11, buffer3, 0, 0x20);
        Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, dst, 0x3e8);
        buffer4 = bytes.getBytes(0x20);
        return Arrays.equals(buffer3, buffer4);

    }

    public static String hashPasswordWithSalt(String password, byte[] salt) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] buffer2;
        if (password == null)
            throw new IllegalArgumentException("password");

        for (int i = 0; i < 0x10; ++i) {
            salt[i] = (byte) 1000;
        }

        Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, salt, 0x3e8);
        salt = bytes.getSalt();
        buffer2 = bytes.getBytes(0x20);
        byte[] dst = new byte[0x31];
        System.arraycopy(salt, 0, dst, 1, 0x10);
        System.arraycopy(buffer2, 0, dst, 0x11, 0x20);
        return Base64.encodeBase64String(dst);
    }

}
