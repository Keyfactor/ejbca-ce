<%
    // Version: $Id$
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@ page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.authorization.control.StandardRules
"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<%
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
%>

<html>
<f:view>
    <head>
    <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
    <base href="<%= ejbcawebbean.getBaseUrl() %>" />
    <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
    <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
    <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
    <script>
    /** Prevent form submission if enter is pressed in form and instead clicks on the button right of the inputText instead..) */
    function preventSubmitOnEnter(o, e) {
    if (typeof e == 'undefined' && window.event) {
    e = window.event;
    }
    if (e.keyCode == 13) {
    e.returnValue = false;
    o.nextSibling.click();
    }
    }
    </script>

    </head>
    <body>
    <jsp:include page="../adminmenu.jsp"/>
    <div class="main-wrapper">
        <div class="container">
            <h1>
                <h:outputText value="#{web.text.ACME_MANAGEALIASES}"
                              rendered="#{systemConfigMBean.allowedToEditSystemConfiguration}"/>
                <h:outputText value="#{web.text.SCEP_VIEW_ALIASES}"
                              rendered="#{!systemConfigMBean.allowedToEditSystemConfiguration}"/>
                <%= ejbcawebbean.getHelpReference("/ACME.html") %>
            </h1>
            <div class="message"><h:messages layout="table" errorClass="alert"/></div>
            <h3><h:outputText value="#{web.text.ACME_LISTOFALIASES}"/></h3>

            <h:form id="aliases">

                <h:inputHidden id="newAlias" value="#{acmeConfigMBean.newAlias}">
                    <f:validator validatorId="legalCharsValidator" />
                </h:inputHidden>

                <h:inputHidden id="currentAliasStr" value="#{acmeConfigMBean.currentAliasStr}">
                    <f:validator validatorId="legalCharsValidator" />
                </h:inputHidden>

                <h:dataTable value="#{acmeConfigMBean.aliasGuiList}" var="alias" styleClass="grid">

                    <h:column headerClass="listColumn1">
                        <f:facet name="header">
                            <h:outputText value="#{web.text.ACME_ALIAS}"/>
                        </f:facet>

                        <h:outputLink value="adminweb/sysconfig/acmealiasconfiguration.jsf?alias=#{alias.alias}">
                            <h:outputText value="#{alias.alias}" title="#{alias.alias}"/>
                        </h:outputLink>
                    </h:column>

                    <h:column>
                        <f:facet name="header"><h:outputText value="#{web.text.ACTIONS}"/></f:facet>
                        <h:commandLink action="#{acmeConfigMBean.renameAlias}" rendered="#{systemConfigMBean.allowedToEditSystemConfiguration}"
                                       onclick="return getInputToField('aliases:newAlias','#{web.text.ACME_ENTERNEWALIAS}', '#{web.text.ONLYCHARACTERS}') && getInsertIntoField('aliases:currentAliasStr','#{alias.alias}', '#{web.text.ONLYCHARACTERS}');"
                                       styleClass="commandLink" title="#{web.text.SCEP_RENAME_ALIAS}">
                            <h:outputText value="#{web.text.RENAME}"/>
                        </h:commandLink>
                        <h:commandLink action="#{acmeConfigMBean.deleteAlias}" onclick="return confirm('#{web.text.AREYOUSURE}') && getInsertIntoField('aliases:currentAliasStr','#{alias.alias}', '#{web.text.ONLYCHARACTERS}');"
                                       styleClass="commandLink" title="#{web.text.SCEP_DELETE_ALIAS}" rendered="#{systemConfigMBean.allowedToEditSystemConfiguration}">
                            <h:outputText value="#{web.text.DELETE}"/>
                        </h:commandLink>
                    </h:column>

                </h:dataTable>
                <br/>
                <h:commandLink action="#{acmeConfigMBean.addAlias}" styleClass="commandLink" title="#{web.text.SCEP_ADD_ALIAS}"
                               onclick="return getInputToField('aliases:newAlias','#{web.text.ACME_ENTERNEWALIAS}', '#{web.text.ONLYCHARACTERS}');"
                               rendered="#{systemConfigMBean.allowedToEditSystemConfiguration}">
                    <h:outputText value="#{web.text.ADD}"/>
                </h:commandLink>

            </h:form>
            <h:panelGroup/>

            <h3><h:outputText value="#{web.text.ACME_GLOBAL_CONFIGS}"/></h3>
            <h:form id="acmeConfigs" rendered="#{acmeConfigMBean.allowedToEdit}">

                <h:panelGrid columns="2">
                    <h:outputLabel for="defaultConfig" value="#{web.text.ACME_DEFAULT_CONFIG}" />
                    <h:panelGroup id="defaultConfig"  >
                        <h:panelGroup >
                            <h:selectOneMenu id="selectOneMenuEEP" value="#{acmeConfigMBean.globalInfo.defaultAcmeConfiguration}">
                                <f:selectItems value="#{acmeConfigMBean.aliasSeletItemList}"/>
                            </h:selectOneMenu>
                        </h:panelGroup>
                    </h:panelGroup>

                    <h:outputLabel for="replayNonce" value="#{web.text.ACME_REPLAY_NONCE_VALIDITY}" />
                    <h:panelGroup id="replayNonce" >
                        <h:inputText title="#{web.text.FORMAT_INTEGER}" value="#{acmeConfigMBean.globalInfo.replayNonceValidity}" validatorMessage="#{web.text.ONLYNUMBERS_INNONCEVALIDITY}">
                            <f:validateLongRange minimum="0" maximum="9223372036854775807"/>
                        </h:inputText>
                    </h:panelGroup>
                    <h:panelGroup>
                        <h:commandButton action="#{acmeConfigMBean.saveGlobalConfigs}" value="#{web.text.SAVE}"/>
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