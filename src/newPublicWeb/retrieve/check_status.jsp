<%@ include file="header.jsp" %>
<h1 class="title">Check Certificate Status</h1>
<p>Enter the serial number of a certificate (in hexadecimal form) and click 'Check revocation'
  to see if the certificate is revoked.
  <br />
<form action="check_status_result.jsp" enctype=x-www-form-encoded method="GET">
  <fieldset>
    <legend>Certificate data</legend>
	<input type="hidden" name="cmd" value="revoked" />
	<label for="issuer">Issuer DN</label>
	<input name="issuer" type="text" size="40" accesskey="i"/>
	<br>
	<label for="serno">Serial No.</label>
	<input name="serno" type="text" size="40" accesskey="s"/>
	<br>
	<br>
	<label for="dummy"></label>
	<input type="submit" value="Check revocation">
  </fieldset>
</form>
<%@ include file="footer.inc" %>

