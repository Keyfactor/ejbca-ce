<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,
                                           org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" />
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
 helpbean.authorizedToApprovalPages();
%>
<html>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>">
</head>
<f:view>
<body>
<h1 align="center"><h:outputText value="#{web.text.ACTIVATECAS}"/></h1>
	<h:form>
	<h:dataTable border="0" value="#{cAActivationMBean.hasMessages}" var="item" style="right: auto; left: auto">
	     	<h:column>
	     		<td>
	     		<h:outputText value="#{web.text.MESSAGE}: "/>
	     		<h:outputText value="#{item.name}: "></h:outputText>
				</td>	     	
	     	</h:column>
	     	<h:column>
	     	<h:outputText value="#{item.CAActivationMessage}"></h:outputText>
	     	</h:column>
	     </h:dataTable>
	<h:dataTable border="1" value="#{cAActivationMBean.authorizedCAWrappers}" var="item" style="border-collapse: collapse; right: auto; left: auto">
	  			<h:column>
	    			<f:facet name="header">
	    				<h:outputText value="#{web.text.CA}" />
	    			</f:facet>
	    			<h:outputText value="#{item.name}"></h:outputText>
	    		</h:column>
	  			<h:column>
	    			<f:facet name="header">
	    				<h:outputText value="#{web.text.CASTATUS}" />
	    			</f:facet>
	    			<table width="90px" border="0">
	    			<tr>
	    			<td>
	    			<h:outputText value="#{item.status}"></h:outputText>
	    			</td>
	    			<td align="right">
	    			<h:graphicImage height="14" width="14" url="#{item.statusImg}" style="border-width:0"/>
	    			</td>
	    			</tr>
	    			</table>
		    		</h:column>
	    		<h:column>
	    			<f:facet name="header">
	    				<h:outputText value="#{web.text.CATOKENSTATUS}" />
	    			</f:facet>
	    			<table width="100px" border="0">
	    			<tr>
	    			<td>
	    			<h:outputText value="#{item.tokenStatus}"></h:outputText>
	    			</td>
	    			<td align="right">
	    			<h:graphicImage height="14" width="14" url="#{item.tokenStatusImg}" style="border-width:0"/>
	    			</td>
	    			</tr>
	    			</table>
	    		</h:column>
	    		<h:column>
	    		<f:facet name="header">
	    	 		<h:outputText value="#{web.text.ACTIVATEORMAKEOFFLINE}" />
	    		</f:facet>
	    		<h:selectOneRadio id="align" value="#{item.activateOption}">
  					<f:selectItem itemLabel="#{web.text.ACTIVATE}" itemValue="#{cAActivationMBean.activate}"/>
  					<f:selectItem itemLabel="#{web.text.MAKEOFFLINE}" itemValue="#{cAActivationMBean.makeoffline}"/>
  					<f:selectItem itemLabel="#{web.text.NOCHANGE}" itemValue="#{cAActivationMBean.keepcurrent}"/>
				</h:selectOneRadio>
	    		</h:column>
	    		<h:column>
	    		<f:facet name="header">
	    	 		<h:outputText value="#{web.text.MONITORIFCAACTIVE}" />
	    		</f:facet>
	    		<h:selectBooleanCheckbox value="#{item.monitored}" />
	    		<h:outputText value="#{web.text.MONITORED}" />
	    		</h:column>
	         </h:dataTable>
	     <br/>
	     <table border="1" style="border-collapse: collapse; right: auto; left: auto">
	         <tr>
	         <td>
	           <h:outputText value="#{web.text.AUTHENTICATIONCODE}:" style="right: 4px"></h:outputText>
	         </td>
	         <td>
	           <h:inputSecret id="password" value="#{cAActivationMBean.authenticationCode}" />
	         </td>
	         <td>
	           <h:commandButton id="submit" action="#{cAActivationMBean.apply}" value="Apply" />
	         </td>
	         </tr>
	     </table>
	     <br>
	     
	 </h:form>
</body>
</f:view>
</html>
