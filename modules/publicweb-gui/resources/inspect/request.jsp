 <%@ include file="header.jsp" %>
  <h1 class="title">Inspect Certificates/CSRs</h1>
  <p>Upload request to dump contents.</p>
  <form action="request_result.jsp" enctype="multipart/form-data" method="post">
    <fieldset>
      <legend>Certificate or CSR file:</legend>
	
	  <label for="reqfile"></label>
	  <input type="FILE" name="reqfile" id="reqfile"></input>
	
       <br />
       <label for="ok"></label>
       <input type="submit" id="ok" value="OK" name="submit" />
    </fieldset>
  </form>
</div>
<%@ include file="footer.inc" %>
