package pgp.ra;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

/**
 * @author Adler Fleurant
 * @since 1.0
 */
public enum CompressionAlgorithm {
    ZIP(CompressionAlgorithmTags.ZIP),
    ZLIB(CompressionAlgorithmTags.ZLIB),
    BZIP2(CompressionAlgorithmTags.BZIP2),
    UNCOMPRESSED(CompressionAlgorithmTags.UNCOMPRESSED);

    public int getCode() {
        return code;
    }

    private final int code;

    CompressionAlgorithm(int code) {
        this.code = code;
    }
}
