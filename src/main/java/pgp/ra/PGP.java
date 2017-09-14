package pgp.ra;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * This class consists exclusively of static methods for obtaining {@link PGPEncryptorBuilder
 * PGPEncryptorBuilder} and {@link PGPDecryptorBuilder PGPDecryptorBuilder} for building {@link
 * PGPEncryptor PGPEncryptor) and {@link PGPDecryptor PGPDecryptor) for the PGP encoding scheme.
 * The implementation of this class supports PGP encryption and decryption as specified in
 * <a href="https://tools.ietf.org/html/rfc4880">RFC 4880</a>. The support is limited to the use case describe in
 * section <a href="https://tools.ietf.org/html/rfc4880#section-2.1">section 2.1</a> of the mentioned document.
 * <p>
 * <p> Unless otherwise noted, passing a {@code null} argument to a method of this class will cause a
 * {@link java.lang.NullPointerException NullPointerException} to be thrown.
 *
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGP {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PGPEncryptorBuilder getEncoderBuilder(){
        return new PGPEncryptorBuilder();
    }

    public static PGPDecryptorBuilder getDecoderBuilder(){
        return new PGPDecryptorBuilder();
    }

    public static PGPSignerBuilder getSignerBuilder(){
        return new PGPSignerBuilder();
    }
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

}
