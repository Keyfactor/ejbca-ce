<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.config.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,
                                           org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper,
                                           org.ejbca.core.model.authorization.AccessRulesConstants" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" />
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.REGULAR_ACTIVATECA); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
%>
<html>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>

<f:view>
<body>

<h1><h:outputText value="#{web.text.ACTIVATECAS}"/></h1>

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
	<div id="activation">
	<h:dataTable styleClass="grid" value="#{cAActivationMBean.authorizedCAWrappers}" var="item" style="border-collapse: collapse; right: auto; left: auto">
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
	    			<h:graphicImage height="16" width="16" url="#{item.statusImg}" style="border-width:0"/>
	    			<h:outputText value="#{item.status}"></h:outputText>
		    		</h:column>
	    		<h:column>
	    			<f:facet name="header">
	    				<h:outputText value="#{web.text.CATOKENSTATUS}" />
	    			</f:facet>
	    			<h:graphicImage height="16" width="16" url="#{item.tokenStatusImg}" style="border-width:0"/>
	    			<h:outputText value="#{item.tokenStatus}"></h:outputText>
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
			</div>

			<div id="code">
	           <h:outputText value="#{web.text.AUTHENTICATIONCODE}"></h:outputText>
	           <h:inputSecret id="password" value="#{cAActivationMBean.authenticationCode}" />
	           <h:commandButton id="submit" action="#{cAActivationMBean.apply}" value="#{web.text.APPLY}" />
			</div>

	 </h:form>

	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
   
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
