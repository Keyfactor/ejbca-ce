<%@ include file="header.jsp" %>
  <h1 class="title">List Certificates</h1>
  <div align="center">
  <form action="list_certs_result.jsp" enctype=x-www-form-encoded method="GET">
    <div align="center">Give subject DN to list users certificates.<br>
      <input type="hidden" name="cmd" value="listcerts">
      Subject DN
      <input name="subject" type=text size=30 value="c=SE, O=AnaTom, CN=foo">
      <br>
      <input type="submit" value="OK" name="submit">
    </div>
  </form>
</div>
<%@ include file="footer.inc" %>
