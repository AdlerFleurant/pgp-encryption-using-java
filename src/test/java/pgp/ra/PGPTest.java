package pgp.ra;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
class PGPTest {

    private static String publicKeyFilename;
    private static String secretKeyFilename;
    private static String nonEncryptedFilename;
    private static PGPDecryptor PGPDecryptor;
    private static PGPEncryptor armoredIntegrityPGPEncryptor;
    private static PGPEncryptor zipIntegrityPGPEncryptor;
    private static PGPEncryptor armoredZipIntegrityPGPEncryptor;

    @BeforeAll
    static void init() throws IOException, PGPException {
        publicKeyFilename = PGPTest.class.getClassLoader().getResource("0x138DFA83-pub.asc").getFile();
        secretKeyFilename = PGPTest.class.getClassLoader().getResource("0x138DFA83-sec.asc").getFile();
        nonEncryptedFilename = PGPTest.class.getClassLoader().getResource("sampleNonEncoded.txt").getFile();
        PGPDecryptor = PGP.getDecoderBuilder()
                .withSecretKey(secretKeyFilename)
                .withPassphrase("D@t@sh@re")
                .build();

        armoredIntegrityPGPEncryptor = PGP.getEncoderBuilder()
                .withPublicKey(publicKeyFilename)
                .withArmoredEncryption()
                .withIntegrityCheck()
                .encryptWith(SymmetricKeyAlgorithm.CAST5)
                .build();

        zipIntegrityPGPEncryptor = PGP.getEncoderBuilder()
                .withPublicKey(publicKeyFilename)
                .compressedWith(CompressionAlgorithm.ZIP)
                .withIntegrityCheck()
                .encryptWith(SymmetricKeyAlgorithm.CAST5)
                .build();

        armoredZipIntegrityPGPEncryptor = PGP.getEncoderBuilder()
                .withPublicKey(publicKeyFilename)
                .compressedWith(CompressionAlgorithm.ZIP)
                .withIntegrityCheck()
                .encryptWith(SymmetricKeyAlgorithm.CAST5)
                .build();
    }

    @Test
    @DisplayName("An armored, compressed message with integrity check should be able to be decoded")
    public void testArmoredZipIntegrityEncodeDecode() throws Exception {

        byte[] encodedData = armoredZipIntegrityPGPEncryptor.encode(new File(nonEncryptedFilename));

        assertArrayEquals(FileUtils.readFileToByteArray(new File(nonEncryptedFilename)), PGPDecryptor.decode(encodedData));
    }

    @Test
    @DisplayName("A compressed message with integrity check should be able to be decoded")
    public void testZipIntegrityEncodeDecode() throws Exception {

        byte[] encodedData = zipIntegrityPGPEncryptor.encode(new File(nonEncryptedFilename));

        assertArrayEquals(FileUtils.readFileToByteArray(new File(nonEncryptedFilename)), PGPDecryptor.decode(encodedData));
    }

    @Test
    @DisplayName("An armored message with integrity check should be able to be decoded")
    public void testArmoredIntegrityEncodeDecode() throws Exception {

        byte[] encodedData = armoredIntegrityPGPEncryptor.encode(new File(nonEncryptedFilename));

        assertArrayEquals(FileUtils.readFileToByteArray(new File(nonEncryptedFilename)), PGPDecryptor.decode(encodedData));
    }
}