<%
    // Version: $Id$
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.authorization.control.AuditLogRules,
org.cesecore.authorization.control.StandardRules
"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<%
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
%>
<html>
<f:view>
    <head>
        <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}"/></title>
        <base href="<%= ejbcawebbean.getBaseUrl() %>"/>
        <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />"/>
        <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png"/>
        <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
    </head>
    <body>
    <jsp:include page="../adminmenu.jsp"/>
    <div class="main-wrapper">
        <div class="container">
            <h1>
                <h:outputText value="#{acmeConfigMBean.currentAlias.alias}"/>
            </h1>

            <div class="message"><h:messages layout="table" errorClass="alert"/></div>
            <h:form id="currentAliasForm">
                <h:panelGrid columns="2">
                    <h:outputLink value="adminweb/sysconfig/acmeconfiguration.jsf"><h:outputText value="#{web.text.ACME_ALIAS_NAV_BACK}"/></h:outputLink>
                    <h:commandButton action="#{acmeConfigMBean.toggleCurrentAliasEditMode}" value="#{web.text.CRYPTOTOKEN_NAV_EDIT}" rendered="#{!acmeConfigMBean.currentAliasEditMode && acmeConfigMBean.allowedToEdit}"/>

                    <h:panelGroup id="placeholder1" />
                    <h:panelGroup id="placeholder2" rendered="#{!acmeConfigMBean.currentAliasEditMode && acmeConfigMBean.allowedToEdit}"/>

                    <h:outputLabel for="eep" value="#{web.text.ACME_END_ENTITY_PROFILE}" />
                    <h:panelGroup id="eep"  >
                        <h:panelGroup >
                            <h:selectOneMenu id="selectOneMenuEEP" value="#{acmeConfigMBean.currentAlias.endEntityProfileId}"
                                             disabled="#{!acmeConfigMBean.currentAliasEditMode}">
                                <f:selectItems value="#{acmeConfigMBean.authorizedEEProfileNames}"/>
                            </h:selectOneMenu>
                        </h:panelGroup>
                    </h:panelGroup>

                    <h:outputLabel for="preautorisation" value="#{web.text.ACME_PREAUTHORIZATION_ALLOWED}" />
                    <h:selectBooleanCheckbox id="preautorisation" value="#{acmeConfigMBean.currentAlias.preAuthorizationAllowed}" disabled="#{!acmeConfigMBean.currentAliasEditMode}" />

                    <h:outputLabel for="accbinding" value="#{web.text.ACME_REQUIRE_EXTERNAL_ACCOUNT_BINDING}" />
                    <h:selectBooleanCheckbox id="accbinding" value="#{acmeConfigMBean.currentAlias.preAuthorizationAllowed}" disabled="#{!acmeConfigMBean.currentAliasEditMode}" />

                    <h:outputLabel for="wildcard" value="#{web.text.ACME_WILDCARD_CERTIFICATE_ISSUANCE_ALLOWED}" />
                    <h:selectBooleanCheckbox id="wildcard" value="#{acmeConfigMBean.currentAlias.wildcardCertificateIssuanceAllowed}" disabled="#{!acmeConfigMBean.currentAliasEditMode}" />

                    <h:outputLabel for="webUrl" value="#{web.text.ACME_WEBSITE_URL}" />
                    <h:panelGroup id="webUrl" >
                        <h:inputText  value="#{acmeConfigMBean.currentAlias.urlTemplate}" size="45" rendered="#{acmeConfigMBean.currentAliasEditMode}">
                            <f:validator validatorId="urlValidator"/>
                        </h:inputText>
                        <h:outputText value="#{acmeConfigMBean.currentAlias.urlTemplate}" rendered="#{!acmeConfigMBean.currentAliasEditMode}"/>
                    </h:panelGroup>

                    <h:outputLabel for="termsUrl" value="#{web.text.ACME_TERMS_URL}" />
                    <h:panelGroup id="termsUrl" >
                        <h:inputText  value="#{acmeConfigMBean.currentAlias.termsOfServiceUrl}" size="45" rendered="#{acmeConfigMBean.currentAliasEditMode}">
                            <f:validator validatorId="urlValidator"/>
                        </h:inputText>
                        <h:outputText value="#{acmeConfigMBean.currentAlias.termsOfServiceUrl}" rendered="#{!acmeConfigMBean.currentAliasEditMode}"/>
                    </h:panelGroup>

                    <h:outputLabel for="versionApproval" value="#{web.text.ACME_TERMS_APPROVAL}" />
                    <h:selectBooleanCheckbox id="versionApproval" value="#{acmeConfigMBean.currentAlias.tersmOfServiceApproval}" disabled="#{!acmeConfigMBean.currentAliasEditMode}" />

                    
                    <h:outputLabel for="dnsResolver" value="#{web.text.ACME_DNS_RESOLVER}" />
                    <h:panelGroup id="dnsResolver" >
                        <h:inputText  value="#{acmeConfigMBean.currentAlias.dnsResolver}" size="45" rendered="#{acmeConfigMBean.currentAliasEditMode}">
                            <f:validator validatorId="legalCharsValidator"/>
                        </h:inputText>
                        <h:outputText value="#{acmeConfigMBean.currentAlias.dnsResolver}" rendered="#{!acmeConfigMBean.currentAliasEditMode}"/>
                    </h:panelGroup>
                    
                    <h:outputLabel for="dnssecTrustAnchor" value="#{web.text.ACME_DNSSEC_TRUST_ANCHOR}" />
                    <h:panelGroup id="dnssecTrustAnchor" >
                        <h:inputTextarea  value="#{acmeConfigMBean.currentAlias.dnssecTrustAnchor}"  rendered="#{acmeConfigMBean.currentAliasEditMode}"
                        	cols="45" rows="3" >
                            <f:validator validatorId="legalCharsValidator"/>
                        </h:inputTextarea>
                        <h:outputText value="#{acmeConfigMBean.currentAlias.dnssecTrustAnchor}" rendered="#{!acmeConfigMBean.currentAliasEditMode}"/>
                    </h:panelGroup>

                    <h:panelGroup/>

                    <h:panelGroup>
                        <h:commandButton action="#{acmeConfigMBean.cancelCurrentAlias}" value="#{web.text.CANCEL}" rendered="#{acmeConfigMBean.currentAliasEditMode}"/>
                        <h:commandButton action="#{acmeConfigMBean.saveCurrentAlias}" value="#{web.text.SAVE}" rendered="#{acmeConfigMBean.currentAliasEditMode}"/>
                    </h:panelGroup>
                </h:panelGrid>
            </h:form>

        </div> <!-- Container -->

        <% // Include Footer
            String footurl = globalconfiguration.getFootBanner(); %>
        <jsp:include page="<%= footurl %>"/>
    </div> <!-- main-wrapper -->
    </body>
</f:view>
</html>