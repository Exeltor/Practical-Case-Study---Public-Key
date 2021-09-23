import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

public class Test_RSA {
	
	public static void main(String[] args) throws Exception {
		RSALibrary r = new RSALibrary();
		r.generateKeys();
		
		/* Read  public key*/
		Path path = Paths.get("./public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);
		
		/* Read private key */
		path = Paths.get("./private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);

		/* Encryption */

		String textToEncrypt = "Hello World!";
		System.out.println("---------Plain Text----------");
		System.out.println(textToEncrypt);

		// Obtaining encrypted bytestring from plain text
		byte[] encryptedText = r.encrypt(textToEncrypt.getBytes(), publicKey);
		System.out.println("---------Encrypted Text----------");
		// Transforming encrypted bytestring to string, and printing the result
		System.out.println(new String(encryptedText, StandardCharsets.UTF_8));

		// Decrypting enctypted string and transforming the resulting bytestring
		String decryptedText = new String(r.decrypt(encryptedText, privateKey), StandardCharsets.UTF_8);
		System.out.println("---------Decrypted Text----------");
		System.out.println(decryptedText);


		/* Signature */

		String textToSign = "I will be signed";
		byte[] signature = r.sign(textToSign.getBytes(), privateKey);

		String unsignedText = "Am I signed?";
		System.out.print("Signed text check:");
		System.out.println(r.verify(textToSign.getBytes(), signature, publicKey));

		System.out.print("Unsigned text check:");
		System.out.println(r.verify(unsignedText.getBytes(), signature, publicKey));

	}
	
}
