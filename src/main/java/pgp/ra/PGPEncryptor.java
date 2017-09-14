package pgp.ra;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.security.SecureRandom;
import java.util.logging.Logger;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
class PGPEncryptor {
    private static final Logger LOGGER = Logger.getLogger(PGPEncryptor.class.getSimpleName());

    private final PGPPublicKey encryptionKey;
    private final boolean integrityCheck;
    private final boolean armored;
    private final CompressionAlgorithm compressionAlgorithm;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;

    PGPEncryptor(PGPPublicKey encryptionKey, boolean integrityCheck, boolean armored, CompressionAlgorithm compressionAlgorithm, SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        this.encryptionKey = encryptionKey;
        this.integrityCheck = integrityCheck;
        this.armored = armored;
        this.compressionAlgorithm = compressionAlgorithm;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
    }

    public byte[] encode(File src) throws IOException, PGPException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        try (ByteArrayOutputStream bOut = new ByteArrayOutputStream();
             OutputStream out = new EncryptorOutputStream(bOut);
             OutputStream pOut = lData.open(out, PGPLiteralData.BINARY, src);
             FileInputStream in = new FileInputStream(src)
        ) {
            byte[] buf = new byte[4096];

            int len;
            while ((len = in.read(buf)) > 0) {
                pOut.write(buf, 0, len);
            }

            out.close();

            return encode(bOut.toByteArray());
        }
    }

    /**
     * Encodes all bytes from the specified byte array into a newly-allocated byte array using the {@link PGP}
     * encoding scheme. The returned byte array starts with the encoded session key.
     *
     * @param src the byte array to encode
     * @return A newly-allocated byte array containing the resulting
     * encoded bytes.
     */
    private byte[] encode(byte[] src) throws IOException, PGPException {

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm.getCode())
                        .setWithIntegrityPacket(integrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

        ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();

        OutputStream cOut;

        if (armored) {
            ArmoredOutputStream armored = new ArmoredOutputStream(encryptedData);
            cOut = encGen.open(armored, src.length);
            cOut.write(src);
            cOut.close();
            armored.close();
        } else {
            cOut = encGen.open(encryptedData, src.length);
            cOut.write(src);
            cOut.close();

        }

        byte[] bytes = encryptedData.toByteArray();

        System.out.println("Source: " + src.length + ". target: " + bytes.length);
        return bytes;
    }

    private class EncryptorOutputStream extends OutputStream {
        private final OutputStream out;
        PGPCompressedDataGenerator comData;

        private EncryptorOutputStream(OutputStream out) throws IOException {
            if (compressionAlgorithm != CompressionAlgorithm.UNCOMPRESSED) {
                comData = new PGPCompressedDataGenerator(compressionAlgorithm.getCode());
                this.out = comData.open(out);
            } else
                this.out = out;
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
        }

        @Override
        public void write(byte[] b) throws IOException {
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
            out.close();
            if (comData != null)
                comData.close();
        }
    }
}
