import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

public class SM3 {

    public static void main(String[] args) {
        System.out.println(Hex.toHexString(digest(new byte[]{1, 2, 3})));
        System.out.println(Hex.toHexString(digest(new byte[]{1, 2, 3})));
    }

    public static byte[] digest(byte[] input){
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(input, 0, input.length);
        byte[] ret = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(ret, 0);
        return ret;
    }
}
