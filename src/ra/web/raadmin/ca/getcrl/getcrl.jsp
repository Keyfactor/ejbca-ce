<%@page contentType="text/html"%>
<%@page errorPage="../../errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration,
                                              se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.webdist.rainterface.CertificateView,
                                              se.anatom.ejbca.webdist.rainterface.DNFieldExtractor, se.anatom.ejbca.ra.authorization.AuthorizationDeniedException"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<% 
  GlobalConfiguration globalconfiguration = ejbcawebbean.getGlobalConfiguration();
  final String DOWNLOADCRL_LINK             = globalconfiguration.getCaPath() 
                                                  + "/getcrl/getcrl"; %>
<br>
<br>
<br>
<hr>
<br>
<%=ejbcawebbean.getText("GETLATESTCRL") + ", " + ejbcawebbean.getText("NUMBER") + " " + cabean.getLastCRLNumber() +" : " %>
<i><a href="<%=DOWNLOADCRL_LINK%>?cmd=crl" ><%=ejbcawebbean.getText("GETCRL") %></a></i>
<br>