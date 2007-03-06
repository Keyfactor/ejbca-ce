<%@ include file="header.jsp" %>
<h1 class="title">@EJBCA@ fetch latest certificate</h1>

<p>
	Give subject DN to fetch users latest certificate.
</p><p>
	Note that the order or case of element descriptors in the DN (C, O, CN, etc) is unimportant.
	The case of elements themselves, on the other hand, <em>IS</em> important.
</p><p> 
    For example, <tt>cn=foo</tt> is considered equal to <tt>CN=foo</tt> but different from <tt>cn=FOO</tt>.
</p>

<form action="../certdist" enctype="x-www-form-encoded" method="GET">
  <fieldset>
    <legend>Name</legend>
    <input type="hidden" name="cmd" value="lastcert">
    <label for="subject">Subject DN</label>
    <input name="subject" type="text" size="40">
    <br>
    <label for="dummy"></label>
    <input type="submit" value="OK">
  </fieldset>
</form>

<div class="frame">
  <div class="label">Note</div>
  <div class="content">
    <p>If you receive a <i>404-Not found</i> response, it means that
       the subject does not have a certificate in the database. Check your entry to make sure 
       you have specified all the DN components.
    <p>
  </div>
</div>

<%@ include file="footer.inc" %>
