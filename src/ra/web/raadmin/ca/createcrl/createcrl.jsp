<%@page contentType="text/html"%>
<%@page errorPage="../../errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration ,
                                              se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.webdist.rainterface.CertificateView,
                                              se.anatom.ejbca.webdist.rainterface.DNFieldExtractor, se.anatom.ejbca.webdist.ejbcaathorization.AuthorizationDeniedException"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<%!
     final static String BUTTON_CREATECRL      = "buttoncreatecrl";
%>
<%   
     GlobalConfiguration globalconfiguration = ejbcawebbean.getGlobalConfiguration();
     final String CREATECRL_LINK               = globalconfiguration .getCaPath() 
                                                  + "/createcrl/createcrl.jsp";
     final String CAFUNCTIONS_LINK             = globalconfiguration .getCaPath() 
                                                  + "/cafunctions.jsp";
%>

<br>
<br>
<br>
<hr>
<br>
<form name='createcrl' method=GET action='<%=CAFUNCTIONS_LINK %>'>
<%=ejbcawebbean.getText("CREATENEWCRL") + " : " %>
<input type='submit' name='<%=BUTTON_CREATECRL %>' value='<%=ejbcawebbean.getText("CREATECRL") %>'>
</form>
<br>