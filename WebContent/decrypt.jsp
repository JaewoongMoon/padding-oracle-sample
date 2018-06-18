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
<h1> hex文字列をmsgパラメーターで渡してください。 3DESで解読します。</h1>
msg パラメーターの値 : 
<%
	String msg = request.getParameter("msg");
	out.println(msg);
	if (msg != null){
%>
<br>
3DESで解読された文字列 : 
<%
	byte[] encrypted = ByteUtil.hexToBytes(msg);
	String decrypted = TripleDes.decrypt(encrypted);
	out.println(decrypted);
%>

<br>
3DESで解読されたhex値 : 
<%
	String hexDecrypted = ByteUtil.bytesToHex(decrypted.getBytes()); 
	//out.println(hexEncrypted);
	out.println(ByteUtil.hexWithSpace(hexDecrypted, 16));
	out.print("<== (" + decrypted.getBytes().length + "Bytes)");
	}
%>
</body>
</html>