package pgp.ra;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchProviderException;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGPDecryptor {
    private static final Logger LOGGER = Logger.getLogger(PGPDecryptor.class.getSimpleName());

    private final PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
    private final char[] password;

    PGPDecryptor(PGPSecretKeyRingCollection pgpSecretKeyRingCollection, char[] password){
        this.pgpSecretKeyRingCollection = pgpSecretKeyRingCollection;
        this.password = password;
    }

    public byte[] decode(byte[] src) throws IOException, NoSuchProviderException {

        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(src));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();

                sKey = this.findSecretKey(pgpSecretKeyRingCollection, pbe.getKeyID(), password);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                InputStream unc = ld.getInputStream();

                OutputStream fOut = new BufferedOutputStream(out);

                Streams.pipeAll(unc, fOut);

                fOut.close();


            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    LOGGER.log(Level.SEVERE, "message failed integrity check");
                } else {
                    LOGGER.log(Level.INFO, "message integrity check passed");
                }
            } else {
                LOGGER.log(Level.WARNING, "no message integrity check");
            }
        } catch (PGPException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }

        return out.toByteArray();
    }

    private PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }
}
