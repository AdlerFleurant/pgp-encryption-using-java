package pgp.ra;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGPEncryptorBuilderTest {
    @Test
    @DisplayName("withPublicKey:String should return NullPointerException when passed null value.")
    void witNullStringPublicKey() throws IOException, PGPException {
        String publicKey = null;
        assertThrows(NullPointerException.class, () -> new PGPEncryptorBuilder().withPublicKey(publicKey));
    }

    @Test
    @DisplayName("withPublicKey:String should return FileNotFoundException if the if the file doesn't exist")
    void withNullStringPublicKeyFileNotFoundException() {
        assertThrows(FileNotFoundException.class, () -> new PGPEncryptorBuilder().withPublicKey("iDoNotExist.asc"));
    }

    @Test
    @DisplayName("withPublicKey:InputStream should return NullPointerException when passed null value.")
    void withNullInputStreamPublicKey() {
        InputStream stream = null;
        assertThrows(NullPointerException.class, () -> new PGPEncryptorBuilder().withPublicKey(stream));
    }

    @Test
    @DisplayName("build should without symmetric key algorithm throwing IllegalStateException.")
    void buildWithoutSymmetricKeyAlgorithm() {
        assertThrows(IllegalStateException.class, () -> new PGPEncryptorBuilder().build());
    }
}
