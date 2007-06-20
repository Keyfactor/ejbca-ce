<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,
                                           org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/ca_functionality/view_certificate"); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
 helpbean.authorizedToReportPages();
%>
<html>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=<%= RequestHelper.getDefaultContentEncoding() %>">
</head>

<f:view>
<body>

<h1 align="center"><h:outputText value="#{web.text.VIEWREPORTS}"/></h1>
  <h4 align="center"><h:messages layout="table" errorClass="alert"/></h4>
  
  <h:form >
    <p align="left">
    <h:panelGroup id="body" >

			<h:outputText/>
			<h:panelGrid columns="3" 
			                styleClass="Table"
			                headerClass="standardTable_Header"
			                footerClass="standardTable_Header"    
			                rowClasses="jsfrow1,jsfrow2"
			                >                     
			  <f:facet name="header">
			    <h:outputText value="Available reports"/>
			    </f:facet>
			  <h:outputText style="font-weight:bold" value="Report"/>
			  <h:outputText style="font-weight:bold" value="Description"/>
			  <h:outputText style="font-weight:bold" value="Database load"/>
			  <h:commandLink id="revokedCertificatesPie"
			    action="#{reportsManagedBean.revokedCertificatesPie}" value="Revoked certificates chart">
			  </h:commandLink>
			  <h:outputText value="Creates a pie chart of how many certificates are revoked" />
			  <h:outputText value="Medium"/>
			  <h:commandLink id="issuedCertificatesListButton"
			    action="#{reportsManagedBean.issuedCertificatesList}" value="Issued certificates">
			  </h:commandLink>
			  <h:outputText value="Creates a list of all issued certificates" />
			  <h:outputText value="High" />
			</h:panelGrid>
	 </h:panelGroup>         
     </p>
  </h:form>
  <hr/>
 
</body>
</f:view>
</html>

