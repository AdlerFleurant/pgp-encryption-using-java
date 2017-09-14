package pgp.ra;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGPSignerBuilder {

    private PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
    private char[] password;
    private SignatureType signatureType = SignatureType.BINARY_DOCUMENT;

    private PGPSignerBuilder(){

    }

    public PGPSignerBuilder signatureType(SignatureType signatureType){
        this.signatureType = signatureType;
        return this;
    }

    public PGPSignerBuilder withSecretKey(String secretKeyLocation) throws IOException, PGPException {
        try(InputStream keyIn = new FileInputStream(secretKeyLocation)) {
            return withSecretKey(keyIn);
        }
    }

    public PGPSignerBuilder withSecretKey(InputStream secretKeyInputStream) throws IOException, PGPException {
        pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(secretKeyInputStream), new JcaKeyFingerprintCalculator());
        return this;
    }

    public PGPSignerBuilder withPassphrase(String password){
        this.password = password.toCharArray();
        return this;
    }

    public PGPSigner build(){
        return new PGPSigner(pgpSecretKeyRingCollection, password, signatureType);
    }
}
