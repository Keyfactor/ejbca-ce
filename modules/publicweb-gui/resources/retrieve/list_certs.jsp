<%@ include file="header.jsp" %>
  <h1 class="title">List certificates</h1>
  <p>Enter the subject DN (e.g., &quot<code>c=SE, O=AnaTom, CN=foo</code>&quot;) to list a user's certificates.</p>
  <form action="list_certs_result.jsp" enctype="x-www-form-encoded" method="post">
    <fieldset>
      <legend>Distinguished name</legend>

      <input type="hidden" name="hidemenu" value="${hidemenu}" />
      <input type="hidden" name="cmd" value="listcerts" />

      <label for="subject">Subject DN</label>
      <input name="subject" id="subject" type="text" size="60" accesskey="s" />

      <br />
      <label for="ok"></label>
      <input type="submit" id="ok" value="OK" name="submit" />
    </fieldset>
  </form>
</div>
<%@ include file="footer.inc" %>
