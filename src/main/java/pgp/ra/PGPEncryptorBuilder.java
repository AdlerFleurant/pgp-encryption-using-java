package pgp.ra;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Optional;
import java.util.stream.StreamSupport;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public class PGPEncryptorBuilder {

    private PGPPublicKey encryptionKey;
    private boolean integrityCheck = false;
    private boolean armored = true;
    private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.NULL;

    PGPEncryptorBuilder(){

    }

    public PGPEncryptorBuilder withPublicKey(String publicKeyFileLocation) throws IOException, PGPException {
        try (InputStream encryptionKeyInputStream = new FileInputStream(publicKeyFileLocation)) {
            this.encryptionKey = readKey(encryptionKeyInputStream);
        }
        return this;
    }

    public PGPEncryptorBuilder withPublicKey(InputStream encryptionKeyInputStream) throws IOException, PGPException {
        this.encryptionKey = readKey(encryptionKeyInputStream);
        return this;
    }

    public PGPEncryptorBuilder withIntegrityCheck(){
        this.integrityCheck = true;
        return this;
    }

    public PGPEncryptorBuilder withoutIntegrityCheck(){
        this.integrityCheck = false;
        return this;
    }


    public PGPEncryptorBuilder withArmoredEncryption(){
        this.armored = true;
        return this;
    }

    public PGPEncryptorBuilder withoutArmoredEncryption(){
        this.armored = false;
        return this;
    }

    public PGPEncryptorBuilder compressedWith(CompressionAlgorithm algorithm){
        this.compressionAlgorithm = algorithm;
        return this;
    }

    public PGPEncryptorBuilder encryptWith(SymmetricKeyAlgorithm symmetricKeyAlgorithm){
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        return this;
    }

    public PGPEncryptor build(){
        if(this.symmetricKeyAlgorithm == SymmetricKeyAlgorithm.NULL){
            throw new IllegalStateException("No symmetricKeyAlgorithm specified");
        }
        return new PGPEncryptor(encryptionKey, armored, integrityCheck, compressionAlgorithm, symmetricKeyAlgorithm);
    }

    static PGPPublicKey readKey(InputStream encryptionKeyData) throws IOException, PGPException {

        Iterator<PGPPublicKeyRing> pgpPublicKeyRingIterator =
                new PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(encryptionKeyData), new JcaKeyFingerprintCalculator()
                ).getKeyRings();

        Iterable<PGPPublicKeyRing> pgpPublicKeyRingIterable = () -> pgpPublicKeyRingIterator;

        Optional<PGPPublicKey> anySuitableEncryptionKey = StreamSupport
                .stream(pgpPublicKeyRingIterable.spliterator(), true)
                .map(PGPPublicKeyRing::getPublicKeys)
                .flatMap(pks -> {
                    Iterable<PGPPublicKey> publicKeys = () -> pks;
                    return StreamSupport.stream(publicKeys.spliterator(), true);
                }).filter(PGPPublicKey::isEncryptionKey)
                .findAny();

        return anySuitableEncryptionKey
                .orElseThrow(() -> new IllegalArgumentException("Can't find encryption key in key ring."));
    }

    public PGPEncryptorBuilder withPublicKey(PGPPublicKey encKey) {
        this.encryptionKey = encKey;
        return this;
    }
}
