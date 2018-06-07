package util;

/**
 * @author	Jae-Woong Moon(mjw8585@gmail.com)
 * @ref 	https://stackoverflow.com/questions/8890174/in-java-how-do-i-convert-a-hex-string-to-a-byte
 * 			https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
 * @Date	2018. 5. 11.	 
 */
public class ByteUtil {

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static byte[] hexToBytes(String hex) { 
		if (hex == null || hex.length() == 0) {
			return null; 
		} 
		byte[] ba = new byte[hex.length() / 2]; 
		for (int i = 0; i < ba.length; i++) { 
			ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16); 
		} 
		return ba; 
	}
	
	public static String hexWithSpace(String hex, int spacePer) {
		if(hex.length() > spacePer) {
			StringBuilder result = new StringBuilder();
			for(int i=0; i < hex.length(); i++) {
				if (i % spacePer == 0) {
					result.append(" ");  // 구분자 
				}
				result.append(hex.charAt(i));
			}
			return result.toString();
			
		}else {
			return hex;
		}
	}
	
	/**
	 * @brief 
	 * @param arg1 : byte string. ex) 0B  
	 * @param arg2 : byte string. ex) AB
	 * @return xored hex string
	 */
	public static String xor(String hex1, String hex2) {
		byte[] arr1 = hexToBytes(hex1);
		byte[] arr2 = hexToBytes(hex2);
		byte[] result = new byte[arr1.length];  
		int i=0;
		for(byte b : arr1) {
			result[i] = (byte) (b ^ arr2[i++]);
		}
		return bytesToHex(result);
		
	}
	
	
	public static void main(String[] args) {
		/*
		String test = "abc";
		System.out.println(bytesToHex(test.getBytes()));
		*/
		
		
		//String test2 = "EF";
		//System.out.println(hexToBytes(test2).length);
		//System.out.println(new String(hexToBytes(test2)));
		
		String test3 = xor("0D", "07");
		System.out.println(test3);
	}
	
}
