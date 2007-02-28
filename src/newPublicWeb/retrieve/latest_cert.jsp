<%@ include file="header.jsp" %>
  <h1 class="title">l@EJBCA@ certificate/CRL retrieval</h1>
<FORM ACTION="../certdist" ENCTYPE=x-www-form-encoded METHOD="GET">
  <p>
  Give subject DN to fetch users latest certificate.<BR>
  Note that the order or case of element descriptors in the DN (C, O, CN, etc) is unimportant.
  The case of elements themselves on the other hand, IS important, e.g. foo != FOO.</p>
    <INPUT TYPE="hidden" NAME="cmd" VALUE="lastcert">
    Subject DN
    <input name="subject" type=text size=30 value="c=SE, O=AnaTom, CN=foo">
    <br>
  <p>If a <i>404-Not found</i> response is received it means that
    the subject
    does not have a certificate in the database.
  <p>
    <INPUT type="submit" value="OK">
</FORM>
<%@ include file="footer.inc" %>
