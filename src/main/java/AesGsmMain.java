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
import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

public class AesGsmMain {
	final static String AES = "AES";
	final static int TAG_SIZE = 16;
	final static int IV_SIZE = 12;
	final static String CYPHER_TRANSFORM = "AES/GCM/NoPadding";
	final static SecureRandom random = new SecureRandom();

	public static void main(String[] args) throws Exception {
		String toBeSecret = "This is a message that no one can know.";
		String notSecretButAuthentic = "This message that everyone knows, but cannot change the value of";

		KeyGenerator keygen = KeyGenerator.getInstance(AES);
		SecretKey aesKey = keygen.generateKey();

		EncodedMessage encrypt = encrypt(aesKey, new DecodedMessage(toBeSecret, notSecretButAuthentic));

		System.out.println(encrypt);

		DecodedMessage decrypt = decrypt(aesKey, encrypt);

		System.out.println(decrypt);
	}

	static EncodedMessage encrypt(SecretKey aesKey, DecodedMessage message) throws Exception {
		byte[] toBeSecret = message.getToBeSecret().getBytes("UTF-8");
		byte[] aad = message.getNotSecretButAuthentic().getBytes("UTF-8");

		byte[] iv = new byte[IV_SIZE];
		random.nextBytes(iv);

		Cipher cipher = Cipher.getInstance(CYPHER_TRANSFORM);
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_SIZE * Byte.SIZE, iv));
		cipher.updateAAD(aad);

		byte[] encrypted = cipher.doFinal(toBeSecret);

		String hexiVEncrypted = hexEncode(concatenate(iv , encrypted));
		return new EncodedMessage(hexiVEncrypted, message.getNotSecretButAuthentic());
	}

	static DecodedMessage decrypt(SecretKey aesKey, EncodedMessage message) throws Exception {
		byte[] ivEncryptedAad = hexDecode(message.getSecret());

		byte[] iv = subArray(ivEncryptedAad, 0, IV_SIZE);
		byte[] encrypted = subArray(ivEncryptedAad, IV_SIZE, ivEncryptedAad.length);
		byte[] aad = message.getNotSecretButAuthentic().getBytes("UTF-8");

		Cipher cipher = Cipher.getInstance(CYPHER_TRANSFORM);
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(16 * Byte.SIZE, iv));
		cipher.updateAAD(aad);

		byte[] output = cipher.doFinal(encrypted);

		return new DecodedMessage(new String(output), new String(aad));
	}

	static class DecodedMessage {
		private final String toBeSecret;
		private final String notSecretButAuthentic;

		public DecodedMessage(String toBeSecret, String notSecretButAuthentic) {
			super();
			this.toBeSecret = toBeSecret;
			this.notSecretButAuthentic = notSecretButAuthentic;
		}

		public String getToBeSecret() {
			return toBeSecret;
		}

		public String getNotSecretButAuthentic() {
			return notSecretButAuthentic;
		}

		@Override
		public String toString() {
			return "Message [toBeSecret=" + toBeSecret + ", notSecretButAuthentic="
					+ notSecretButAuthentic + "]";
		}
	}

	static class EncodedMessage {
		private final String secret;
		private final String notSecretButAuthentic;

		public EncodedMessage(String secret, String notSecretButAuthentic) {
			super();
			this.secret = secret;
			this.notSecretButAuthentic = notSecretButAuthentic;
		}

		public String getSecret() {
			return secret;
		}

		public String getNotSecretButAuthentic() {
			return notSecretButAuthentic;
		}

		@Override
		public String toString() {
			return "EncodedMessage [secret=" + secret + ", notSecretButAuthentic="
					+ notSecretButAuthentic + "]";
		}
	}

	/**
	 * Combine the individual byte arrays into one array.
	 */
	private static byte[] concatenate(byte[]... arrays) {
		int length = 0;
		for (byte[] array : arrays) {
			length += array.length;
		}
		byte[] newArray = new byte[length];
		int destPos = 0;
		for (byte[] array : arrays) {
			System.arraycopy(array, 0, newArray, destPos, array.length);
			destPos += array.length;
		}
		return newArray;
	}

	/**
	 * Extract a sub array of bytes out of the byte array.
	 * @param array the byte array to extract from
	 * @param beginIndex the beginning index of the sub array, inclusive
	 * @param endIndex the ending index of the sub array, exclusive
	 */
	private static byte[] subArray(byte[] array, int beginIndex, int endIndex) {
		int length = endIndex - beginIndex;
		byte[] subarray = new byte[length];
		System.arraycopy(array, beginIndex, subarray, 0, length);
		return subarray;
	}


	private static final char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f' };

	private static String hexEncode(byte[] bytes) {
		final int nBytes = bytes.length;
		char[] result = new char[2 * nBytes];

		int j = 0;
		for (int i = 0; i < nBytes; i++) {
			// Char for top 4 bits
			result[j++] = HEX[(0xF0 & bytes[i]) >>> 4];
			// Bottom 4
			result[j++] = HEX[(0x0F & bytes[i])];
		}

		return new String(result);
	}

	private static byte[] hexDecode(CharSequence s) {
		int nChars = s.length();

		if (nChars % 2 != 0) {
			throw new IllegalArgumentException(
					"Hex-encoded string must have an even number of characters");
		}

		byte[] result = new byte[nChars / 2];

		for (int i = 0; i < nChars; i += 2) {
			int msb = Character.digit(s.charAt(i), 16);
			int lsb = Character.digit(s.charAt(i + 1), 16);

			if (msb < 0 || lsb < 0) {
				throw new IllegalArgumentException("Non-hex character in input: " + s);
			}
			result[i / 2] = (byte) ((msb << 4) | lsb);
		}
		return result;
	}
}