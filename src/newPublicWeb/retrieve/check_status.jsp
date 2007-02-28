<%@ include file="header.jsp" %>
  <h1 class="title">check_status.jsp</h1>
  <FORM ACTION="check_status_result.jsp" ENCTYPE=x-www-form-encoded METHOD="GET">
  <div align="center">Enter serialnumber of certificate and click 'Check revocation'
    to see if the certificate is revoked.
    <INPUT TYPE="hidden" NAME="cmd" VALUE="revoked">
    <BR>
    Issuer DN
    <INPUT NAME="issuer" TYPE=text SIZE=30 VALUE="c=SE, O=AnaTom, CN=TestCA">
    <br>
    Serial number (hex)
    <INPUT NAME="serno" TYPE=text SIZE=30 VALUE="">
    <br>
    <BR>
    <INPUT type="submit" value="Check revocation">
  </div>
</FORM>
<%@ include file="footer.inc" %>
