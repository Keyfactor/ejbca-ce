<%@ include file="header.inc" %>
  <jsp:useBean id="applybean" scope="session" class="org.ejbca.core.model.ApplyBean" />
  <h1 class="title">browser.jsp</h1>
<%  applybean.initialize(request); %>
<%@ include file="footer.inc" %>
