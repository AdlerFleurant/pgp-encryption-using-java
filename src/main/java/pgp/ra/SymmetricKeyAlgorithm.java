package pgp.ra;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public enum SymmetricKeyAlgorithm {
    NULL(SymmetricKeyAlgorithmTags.NULL),
    IDEA(SymmetricKeyAlgorithmTags.IDEA),
    TRIPLE_DES(SymmetricKeyAlgorithmTags.TRIPLE_DES),
    CAST5(SymmetricKeyAlgorithmTags.CAST5),
    BLOWFISH(SymmetricKeyAlgorithmTags.BLOWFISH),
    SAFER(SymmetricKeyAlgorithmTags.SAFER),
    DES(SymmetricKeyAlgorithmTags.DES),
    AES_128(SymmetricKeyAlgorithmTags.AES_128),
    AES_192(SymmetricKeyAlgorithmTags.AES_192),
    AES_256(SymmetricKeyAlgorithmTags.AES_256),
    TWOFISH(SymmetricKeyAlgorithmTags.TWOFISH),
    CAMELLIA_128(SymmetricKeyAlgorithmTags.CAMELLIA_128),
    CAMELLIA_192(SymmetricKeyAlgorithmTags.CAMELLIA_192),
    CAMELLIA_256(SymmetricKeyAlgorithmTags.CAMELLIA_256);

    private int code;

    SymmetricKeyAlgorithm(int code){
        this.code = code;
    }

    public int getCode(){
        return this.code;
    }
}
