<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="ui" uri="http://egovframework.gov/ctl/ui"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="tiles" uri="http://tiles.apache.org/tags-tiles"%>
<c:set var="path" value="${pageContext.request.contextPath}" />

<script type="text/javascript">
$(function(){
var errorMsg = "${errorMsg}";
if (errorMsg != ""){
alert(errorMsg);
}
});

function frmCheck(){
if($("#code").val() == ""){
alert ("코드를 입력해주세요.");
$("#code").focus();
return false;
}
}
</script>

<div id="sign-body">
<div class="form-signin">
<div class="signin-box">
<div id="member-box" class="login-wrap text-cetner">
<div class="form-box">

<!-- login-top -->
<div class="login-top">
    <h3 class="mb_10 fw-normal" style="font-weight:bold;"><i class="xi-mouse"></i>OTP인증</h3>
</div>

<!-- login-form -->
<div class="login-form">
    <form action ="${path}/adms/stat/status/list.do" onsubmit="return frmCheck();">
        <ul class="login">
        <%--
        키 인증 번호 : ${encodeKey } <br>
        바코드 주소 : ${url } <br><br>
        --%>
        <p style="font-weight:bold;">키 인증 번호 :</p>
        <input type="text" class="form-control" name="encodedKey" value="${encodedKey }" readonly="readonly"/>

        <p style="font-weight:bold;">키 인증 번호 :</p>
        <input type="text" class="form-control" name= "${QrUrl}" readonly="readonly"/></br>

        <p style="font-weight:bold;">키 인증 번호 :</p>
        <input type="text" class="form-control" id="code" name="code" placeholder="코드를 입력해주세요" />
        </ul>
        <input type="submit" class="btn btn-lg btn-dark" value="전송" style="margin-top:10px;">
    </form>
</div>

</div>
</div>
</div>
</div>
</div>