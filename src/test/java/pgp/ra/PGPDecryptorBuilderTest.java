package pgp.ra;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
class PGPDecryptorBuilderTest {
    @Test
    @DisplayName("withSecretKey:String should return NullPointerException when passed null value.")
    void witNullStringSecretKey() throws IOException, PGPException {
        String secretKey = null;
        assertThrows(NullPointerException.class, () -> new PGPDecryptorBuilder().withSecretKey(secretKey));
    }

    @Test
    @DisplayName("withSecretKey:String should return FileNotFoundException if the if the file doesn't exist")
    void withNullStringSecretKeyFileNotFoundException() {
        assertThrows(FileNotFoundException.class, () -> new PGPDecryptorBuilder().withSecretKey("iDoNotExist.asc"));
    }

    @Test
    @DisplayName("withSecretKey:InputStream should return NullPointerException when passed null value.")
    void withNullInputStreamSecretKey() {
        InputStream stream = null;
        assertThrows(NullPointerException.class, () -> new PGPDecryptorBuilder().withSecretKey(stream));
    }

    @Test
    @DisplayName("withPassphrase:String should return NullPointerException when passed null value.")
    void withNullStringPassword() {
        String password = null;
        assertThrows(NullPointerException.class, () -> new PGPDecryptorBuilder().withPassphrase(password));
    }

    @Test
    @DisplayName("build should return NullPointerException when passed null value.")
    void build() {

    }
}