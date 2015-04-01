
/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.text.NumberFormat;

/**
 * BenchmarkRsaSign	2000	19,720,933 ns/op
 * BenchmarkRsaVerify	1000	409,857 ns/op
 * BenchmarkEcdsaSign	2000	1,094,302 ns/op
 * BenchmarkEcdsaVerify	1000	1,980,457 ns/op
 *
 * @author rwinch
 *
 */
public class BenchmarkEcdsaVsRsaMain {

	public static void main(String[] args) throws Exception {
		benchmarkRsa();
		benchmarkEcdsa();
	}

	public static void benchmarkRsa() throws Exception {
		KeyPair keyPair = generateRsaKeyPair();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(keyPair.getPrivate());

		byte[] message = hashIt();

		Signature verify = Signature.getInstance("SHA256withRSA");
		verify.initVerify(keyPair.getPublic());

		long start = System.nanoTime();
		int n = 2000;
		for(int i=0;i<n;i++) {
			sign(sign, message);
		}
		long end = System.nanoTime();

		long total = end - start;

		System.out.println("BenchmarkRsaSign\t"+n+"\t" + format(total/n) + " ns/op");

		byte[] expected = sign(sign, message);

		start = System.nanoTime();
		n = 1000;
		for(int i=0;i<n;i++) {
			if(!verify(verify, message, expected)) {
				throw new RuntimeException("This should not happen!");
			}
		}
		end = System.nanoTime();

		total = end - start;

		System.out.println("BenchmarkRsaVerify\t"+n+"\t" + format(total/n) + " ns/op");
	}

	public static void benchmarkEcdsa() throws Exception {
		KeyPair keyPair = generateEcdsaKeyPair();

		String signatureAlg = "SHA256withECDSA";
		Signature sign = Signature.getInstance(signatureAlg);
		sign.initSign(keyPair.getPrivate());

		byte[] message = hashIt();

		Signature verify = Signature.getInstance(signatureAlg);
		verify.initVerify(keyPair.getPublic());


		long start = System.nanoTime();
		int n = 2000;
		for(int i=0;i<n;i++) {
			sign(sign, message);
		}
		long end = System.nanoTime();

		long total = end - start;

		System.out.println("BenchmarkEcdsaSign\t"+n+"\t" + format(total/n) + " ns/op");

		byte[] expected = sign(sign, message);

		start = System.nanoTime();
		n = 1000;
		for(int i=0;i<n;i++) {
			if(!verify(verify, message, expected)) {
				throw new RuntimeException("This should not happen!");
			}
		}
		end = System.nanoTime();

		total = end - start;

		System.out.println("BenchmarkEcdsaVerify\t"+n+"\t" + format(total/n) + " ns/op");
	}

	private static byte[] hashIt() throws Exception {
		String message = "This is a message to be signed and verified by ECDSA!";
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(message.getBytes("UTF-8"));
	}

	private static String format(Number l) {
		return NumberFormat.getInstance().format(l);
	}

	private static boolean verify(Signature signature, byte[] message, byte[] expected) throws Exception {
		signature.update(message);
		return signature.verify(expected);
	}

	private static byte[] sign(Signature signature, byte[] message) throws Exception {
		signature.update(message);
		return signature.sign();
	}

	private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(3048, new SecureRandom());

		return keyGen.generateKeyPair();
	}

	private static KeyPair generateEcdsaKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");

		keyGen.initialize(ecSpec);

		return keyGen.generateKeyPair();
	}
}
