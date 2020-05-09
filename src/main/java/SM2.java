import lombok.SneakyThrows;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SM2 {

    private final KeyPair keyPair;

    public static void main(String[] args) {
        SM2 rsa = new SM2();
        System.out.println(rsa.publicKeyString().length());
        System.out.println(rsa.privateKeyString().length());
        System.out.println(rsa.publicKeyString());
        System.out.println(rsa.privateKeyString());
        System.out.println(rsa.publicKey().length);
        System.out.println(rsa.privateKey().length);
        byte[] sign = sign(rsa.privateKey(), new byte[]{0});
        System.out.println(Hex.toHexString(sign));
        boolean verify = verify(rsa.publicKey(), sign, new byte[]{0});
        System.out.println(verify);
    }

    @SneakyThrows
    public SM2() {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(sm2Spec);
        kpg.initialize(sm2Spec, new SecureRandom());
        keyPair = kpg.generateKeyPair();
    }

    @SneakyThrows
    public byte[] publicKey() {
        return keyPair.getPublic().getEncoded();
    }

    @SneakyThrows
    public byte[] privateKey() {
        return keyPair.getPrivate().getEncoded();
    }

    @SneakyThrows
    public String publicKeyString() {
        return Hex.toHexString(keyPair.getPublic().getEncoded());
    }

    @SneakyThrows
    public String privateKeyString() {
        return Hex.toHexString(keyPair.getPrivate().getEncoded());
    }

    @SneakyThrows
    public static boolean verify(byte[] key, byte[] sign, byte[] source) {
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyFactory instance = KeyFactory.getInstance("EC", provider);
        PublicKey publicKey = instance.generatePublic(spec);
        signature.initVerify(publicKey);
        signature.update(source);
        return signature.verify(sign);
    }

    @SneakyThrows
    public static byte[] sign(byte[] key, byte[] source) {
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyFactory instance = KeyFactory.getInstance("EC", provider);
        PrivateKey privateKey = instance.generatePrivate(spec);
        signature.initSign(privateKey);
        signature.update(source);
        return signature.sign();
    }
}
