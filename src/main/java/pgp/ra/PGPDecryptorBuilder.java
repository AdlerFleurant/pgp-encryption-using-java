package pgp.ra;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A builder for creating {@link PGPDecryptor PGPDecryptor) for PGP scheme. The implementation of this class
 * supports PGP encryption as specified in <a href="https://tools.ietf.org/html/rfc4880">RFC 4880</a>. The support is
 * limited to the use case describe in section <a href="https://tools.ietf.org/html/rfc4880#section-2.1">section 2.1</a>
 * of the mentioned document.
 * <p> Unless otherwise noted, passing a {@code null} argument to a method of this class will cause a
 * {@link java.lang.NullPointerException NullPointerException} to be thrown.
 *
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGPDecryptorBuilder {

    private PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
    private char[] password;

    PGPDecryptorBuilder(){

    }

    public PGPDecryptorBuilder withSecretKey(String secretKeyLocation) throws IOException, PGPException {
        try(InputStream keyIn = new FileInputStream(secretKeyLocation)) {
            return withSecretKey(keyIn);
        }
    }

    public PGPDecryptorBuilder withSecretKey(InputStream secretKeyInputStream) throws IOException, PGPException {
            pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(secretKeyInputStream), new JcaKeyFingerprintCalculator());
        return this;
    }

    public PGPDecryptorBuilder withPassphrase(String password){
        this.password = password.toCharArray();
        return this;
    }

    public PGPDecryptor build(){
        return new PGPDecryptor(pgpSecretKeyRingCollection, password);
    }
}
