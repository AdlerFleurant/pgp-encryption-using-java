package pgp.ra;

import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;

import java.util.logging.Logger;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGPSigner {
    private static final Logger LOGGER = Logger.getLogger(PGPSigner.class.getSimpleName());

    private final PGPSecretKeyRingCollection pgpScretKeyRingCollection;
    private final char[] password;
    private final SignatureType signatureType;

    public PGPSigner(PGPSecretKeyRingCollection pgpSecretKeyRingCollection, char[] password, SignatureType signatureType) {
        this.pgpScretKeyRingCollection = pgpSecretKeyRingCollection;
        this.password = password;
        this.signatureType = signatureType;
    }

    private void sign(){
        PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(encryptionKeys.getPublicKey().getAlgorithm(), sigHashAlgorithmTag).setProvider("BC"));
                     pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, encryptionKeys.getPrivateKey());

    }
}
