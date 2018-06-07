<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="cipher.TripleDes" %>
<%@ page import="util.ByteUtil" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>3DES Decryptor</title>
</head>
<body>
<h1> hex 문자열을 msg파라메터로 전달해주세요. 3DES로 복호화를 시도합니다.</h1>
msg 파라메터 값 : 
<%
	String msg = request.getParameter("msg");
	out.println(msg);
	if (msg != null){
%>
<br>
3DES로 복호화된 문자열 : 
<%
	byte[] encrypted = ByteUtil.hexToBytes(msg);
	String decrypted = TripleDes.decrypt(encrypted);
	out.println(decrypted);
%>

<br>
3DES로 복호화된 헥스 값 : 
<%
	String hexDecrypted = ByteUtil.bytesToHex(decrypted.getBytes()); 
	//out.println(hexEncrypted);
	out.println(ByteUtil.hexWithSpace(hexDecrypted, 16));
	out.print("<== (" + decrypted.getBytes().length + "Bytes)");
	}
%>
</body>
</html>