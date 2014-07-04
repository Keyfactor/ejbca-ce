 <%@ include file="header.jsp" %>
  <h1 class="title">Inspect certificate/CSR</h1>
  <p>Upload request to dump contents.</p>
  <form action="<c:url value="request_result.jsp?hidemenu=${hidemenu}" />" enctype="multipart/form-data" method="post">
    <fieldset>
      <legend>Inspect</legend>
	
	  <label for="reqfile">Certificate or CSR file</label>
	  <input type="file" size="40" name="reqfile" id="reqfile"></input>
	
      <br />
      <label for="ok"></label>
      <input type="submit" id="ok" value="OK" name="submit" />
    </fieldset>
  </form>
</div>
<%@ include file="footer.inc" %>
