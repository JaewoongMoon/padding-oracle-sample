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
<h1>msgパラメータを渡してください。3DESで暗号化されます。</h1>
msg パラメータ値（平文） : 
<%
	String msg = request.getParameter("msg");
	out.println(msg);
	if(msg != null){
%>
<br><br>
平文hex値
<%
	String hexPlain = ByteUtil.bytesToHex(msg.getBytes());
	out.print("(総" + msg.getBytes().length + "Bytes) : ");
	out.println(hexPlain);
%>
<br>
平文hex値（1バイトごとに区分）： 
<%
	out.println(ByteUtil.hexWithSpace(hexPlain, 2));
%>
<br><br>
3DESで暗号化されたhex値
<%
	byte[] encrypted = TripleDes.encrypt(msg);
	String hexEncrypted = ByteUtil.bytesToHex(encrypted); 
	out.println("(総 " + encrypted.length + "Bytes) : ");
	out.println(hexEncrypted);
%>

<br>
3DESで暗号化されたhex値 （8バイトごとに区分） : 
<%
	out.println(ByteUtil.hexWithSpace(hexEncrypted, 16));
	}
%>
</body>
</html>