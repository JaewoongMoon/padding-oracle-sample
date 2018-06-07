<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="cipher.TripleDes" %>
<%@ page import="util.ByteUtil" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
암호화된 헥스 값 : 
<%
	String msg = request.getParameter("msg");
	byte[] encrypted = TripleDes.encrypt(msg);
	String hex = ByteUtil.bytesToHex(encrypted); 
	out.println(hex);
%>
<br>
복호화된 값은 : 
<%
	out.println(TripleDes.decrypt(encrypted));
%> 
</body>
</html>