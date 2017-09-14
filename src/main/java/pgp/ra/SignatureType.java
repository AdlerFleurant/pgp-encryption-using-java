package pgp.ra;

import org.bouncycastle.openpgp.PGPSignature;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public enum SignatureType {
    BINARY_DOCUMENT(PGPSignature.BINARY_DOCUMENT),
    CANONICAL_TEXT_DOCUMENT(PGPSignature.CANONICAL_TEXT_DOCUMENT),
    STAND_ALONE(PGPSignature.STAND_ALONE),

    DEFAULT_CERTIFICATION(PGPSignature.DEFAULT_CERTIFICATION),
    NO_CERTIFICATION(PGPSignature.NO_CERTIFICATION),
    CASUAL_CERTIFICATION(PGPSignature.CASUAL_CERTIFICATION),
    POSITIVE_CERTIFICATION(PGPSignature.POSITIVE_CERTIFICATION),

    SUBKEY_BINDING(PGPSignature.SUBKEY_BINDING),
    PRIMARYKEY_BINDING(PGPSignature.PRIMARYKEY_BINDING),
    DIRECT_KEY(PGPSignature.DIRECT_KEY),
    KEY_REVOCATION(PGPSignature.KEY_REVOCATION),
    SUBKEY_REVOCATION(PGPSignature.SUBKEY_REVOCATION),
    CERTIFICATION_REVOCATION(PGPSignature.CERTIFICATION_REVOCATION),
    TIMESTAMP(PGPSignature.TIMESTAMP);

    private int value;

    SignatureType(int value){
        this.value = value;
    }

    public int getValue(){
        return this.value;
    }
}
