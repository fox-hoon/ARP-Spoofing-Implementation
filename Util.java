package model;

public class Util {
	public static String bytesToString(byte[] bytes) { //byte배열을 문자열 형태로 변환하는 메소드
		StringBuilder sb = new StringBuilder();
		int i=0;
		for(byte b:bytes) {
			sb.append(String.format("%02x ",b&0xff)); //AND연산을 수행하여 바이트스트링 형태로 변환
			if(++i%16==0) sb.append("\n"); //16개의 문자열을 출력하고 줄바꿈
		}
		
		return sb.toString();
	}
}
