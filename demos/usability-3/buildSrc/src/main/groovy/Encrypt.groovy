import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.AsymmetricBlockCipher
import org.bouncycastle.crypto.encodings.PKCS1Encoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.util.encoders.Base64

import java.security.Security

class Encrypt {
    final AsymmetricKeyParameter publicKey

    static {
        Security.addProvider(new BouncyCastleProvider())
    }

    Encrypt(File publicKeyFile) {
        this(new FileInputStream(publicKeyFile))
    }

    Encrypt(InputStream inputStream) {
        this.publicKey = getPublicKeyFromStream(inputStream)
    }

    static AsymmetricKeyParameter getPublicKeyFromStream(InputStream inputStream) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))
        PEMParser parser = new PEMParser(reader)
        SubjectPublicKeyInfo keyInfo = (SubjectPublicKeyInfo) parser.readObject()
        return PublicKeyFactory.createKey(keyInfo.encoded)
    }

    byte[] encrypt(String text) {
        AsymmetricBlockCipher engine = new RSAEngine();
        engine = new PKCS1Encoding(engine);
        engine.init(true, publicKey);
        return engine.processBlock(text.bytes, 0, text.bytes.length)
    }

    String encryptAsString(String text) {
        return Base64.toBase64String(encrypt(text))
    }
}
