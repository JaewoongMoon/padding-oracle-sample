<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="cipher.TripleDes" %>
<%@ page import="util.ByteUtil" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>3DES Encryptor</title>
</head>
<body>
<h1>msg 파라메터를 전달해주세요. 3DES로 암호화됩니다.</h1>
msg 파라메터 값 (평문) : 
<%
	String msg = request.getParameter("msg");
	out.println(msg);
	if(msg != null){
%>
<br><br>
평문 헥스 값
<%
	String hexPlain = ByteUtil.bytesToHex(msg.getBytes());
	out.print("(총 " + msg.getBytes().length + "Bytes) : ");
	out.println(hexPlain);
%>
<br>
평문 헥스 값 (1바이트마다 구분): 
<%
	out.println(ByteUtil.hexWithSpace(hexPlain, 2));
%>
<br><br>
3DES로 암호화된 헥스 값
<%
	byte[] encrypted = TripleDes.encrypt(msg);
	String hexEncrypted = ByteUtil.bytesToHex(encrypted); 
	out.println("(총 " + encrypted.length + "Bytes) : ");
	out.println(hexEncrypted);
%>

<br>
3DES로 암호화된 헥스 값 (8바이트마다 구분) : 
<%
	out.println(ByteUtil.hexWithSpace(hexEncrypted, 2));
	}
%>
</body>
</html>