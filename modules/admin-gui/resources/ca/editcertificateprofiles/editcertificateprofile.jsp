<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" %>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" %>
<%@page import="org.ejbca.config.GlobalConfiguration" %>
<%@page import="org.ejbca.ui.web.RequestHelper" %>
<%@page import="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" %>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<%
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITCERTIFICATEPROFILES);
  cabean.initialize(ejbcawebbean);
  RequestHelper.setDefaultCharacterEncoding(request);
%>
<html>
<head>
  <title><c:out value="<%=globalconfiguration.getEjbcaTitle()%>" /></title>
  <base href="<%=ejbcawebbean.getBaseUrl()%>"/>
  <link rel="stylesheet" type="text/css" href="<%=ejbcawebbean.getCssFile()%>"/>
  <script type="text/javascript" src="<%=globalconfiguration.getAdminWebPath()%>ejbcajslib.js"></script>
  <style type="text/css">
  	input[type='checkbox'].checkBoxOverlay {
  		-moz-user-focus: ignore;
  	}
  	input[type='submit'].checkBoxOverlay {
  		vertical-align: text-bottom;
  		${web.legacyInternetExplorer ? '' : 'position:relative; z-index: 1; left: -20px;'}
  		${web.legacyInternetExplorer ? 'color: #000;' : 'color: transparent; background-color: transparent; border: 0px;'}
  		width: 20px;
  		height: 20px;
  		font-size: 8px;
  		padding: 0px;
  		margin: 0px;
  		
  	}
  	label.checkBoxOverlay {
  		${web.legacyInternetExplorer ? '' : 'position:relative; z-index: 0; left: -20px;'}
  	}
  	label.subItem {
  		padding-left: 10px;
  	}
  </style>
</head>
<f:view>
<body>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>

<div align="center">
  <h2><h:outputText value="#{web.text.EDITCERTIFICATEPROFILE}"/></h2>
  <h3><h:outputText value="#{web.text.CERTIFICATEPROFILE}: #{certProfileBean.selectedCertProfileName}"/></h3>
</div>

<h:form id="cpf">
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<h:panelGroup/>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.caPath}/editcertificateprofiles/editcertificateprofiles.jsf">
			<h:outputText value="#{web.text.BACKTOCERTIFICATEPROFILES}"/>
		</h:outputLink>

		<h:outputLabel for="certificateProfileId" value="#{web.text.CERTIFICATEPROFILEID}"/>
		<h:outputText id="certificateProfileId" value="#{certProfileBean.selectedCertProfileId}"/>

		<h:outputLabel for="selecttype" value="#{web.text.TYPE}"/>
		<h:panelGroup id="selecttype">
			<h:commandButton rendered="#{certProfileBean.typeEndEntityAvailable}" disabled="#{certProfileBean.typeEndEntity}"
				action="#{certProfileBean.setTypeEndEntity}" value="#{certProfileBean.typeEndEntity?'✓':' '}#{web.text.ENDENTITY}"/>
			<h:commandButton rendered="#{certProfileBean.typeSubCaAvailable}" disabled="#{certProfileBean.typeSubCa}"
				action="#{certProfileBean.setTypeSubCa}" value="#{certProfileBean.typeSubCa?'✓':' '}#{web.text.SUBCA}"/>
			<h:commandButton rendered="#{certProfileBean.typeRootCaAvailable}" disabled="#{certProfileBean.typeRootCa}"
				action="#{certProfileBean.setTypeRootCa}" value="#{certProfileBean.typeRootCa?'✓':' '}#{web.text.ROOTCA}"/>
			<h:commandButton rendered="#{certProfileBean.typeHardTokenAvailable}" disabled="#{certProfileBean.typeHardToken}"
				action="#{certProfileBean.setTypeHardToken}" value="#{certProfileBean.typeHardToken?'✓':' '}#{web.text.ROOTCA}"/>
		</h:panelGroup>

		<h:outputLabel for="selectavailablebitlengths" value="#{web.text.AVAILABLEBITLENGTHS}"/>
		<h:selectManyListbox id="selectavailablebitlengths" value="#{certProfileBean.certificateProfile.availableBitLengths}" size="5">
			<f:selectItems value="#{certProfileBean.availableBitLengthsAvailable}"/>
		</h:selectManyListbox>

		<h:outputLabel for="selectsignaturealgorithm" value="#{web.text.SIGNATUREALGORITHM}"/>
		<h:selectOneMenu id="selectsignaturealgorithm" value="#{certProfileBean.signatureAlgorithm}">
			<f:selectItems value="#{certProfileBean.signatureAlgorithmAvailable}"/>
		</h:selectOneMenu>

		<h:panelGroup>
			<h:outputLabel for="textfieldvalidity" value="#{web.text.CERT_VALIDITY}"/>
			<h:outputText value="#{web.text.FORMAT_TIME_YMD} #{web.text.ORENDDATE}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Validity") %>
		</h:panelGroup>
		<h:panelGroup>
			<h:inputText id="textfieldvalidity" value="#{certProfileBean.validity}" title="#{web.text.FORMAT_TIME_YMD} #{web.text.OR} #{web.text.FORMAT_ISO8601}" size="25" maxlength="255"/>
			<h:panelGroup styleClass="help">
				<h:outputText value="#{web.text.DATE_HELP}"/>
				<h:outputText value="#{web.ejbcaWebBean.dateExample}"/>
			</h:panelGroup>
		</h:panelGroup>

	</h:panelGrid>
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- Authorizations --%>

		<h:outputLabel for="header_permissions" value="#{web.text.PERMISSIONS}" style="font-weight: bold;"/>
		<h:panelGroup id="header_permissions"/>

		<h:panelGroup>
			<h:outputLabel for="checkallowvalidityoverridegroup" value="#{web.text.ALLOWVALIDITYOVERRIDE}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Validity") %>
		</h:panelGroup>
		<h:panelGroup id="checkallowvalidityoverridegroup">
			<h:selectBooleanCheckbox id="checkallowvalidityoverride" value="#{certProfileBean.certificateProfile.allowValidityOverride}"/>
			<h:outputLabel for="checkallowvalidityoverride" value="#{web.text.ALLOW} "/>
		</h:panelGroup>

		<h:panelGroup>
			<h:outputLabel for="checkallowextensionoverridegroup" value="#{web.text.ALLOWEXTENSIONOVERRIDE}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Allow%20extension%20override") %>
		</h:panelGroup>
		<h:panelGroup id="checkallowextensionoverridegroup">
			<h:selectBooleanCheckbox id="checkallowextensionoverride" value="#{certProfileBean.certificateProfile.allowExtensionOverride}"/>
			<h:outputLabel for="checkallowextensionoverride" value="#{web.text.ALLOW} "/>
		</h:panelGroup>

		<h:panelGroup>
			<h:outputLabel for="allowcertserialnumberoverridegroup" value="#{web.text.ALLOWCERTSERIALNUMBEROVERRIDE}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Allow%20certificate%20serial%20number%20override") %>
		</h:panelGroup>
		<h:panelGroup id="allowcertserialnumberoverridegroup">
			<h:selectBooleanCheckbox rendered="#{!certProfileBean.uniqueCertificateSerialNumberIndex}" id="allowcertserialnumberoverridefalse"
				value="false" disabled="true"/>
			<h:outputLabel rendered="#{!certProfileBean.uniqueCertificateSerialNumberIndex}" for="allowcertserialnumberoverridefalse" value="#{web.text.ALLOW} "/>
			<h:selectBooleanCheckbox rendered="#{certProfileBean.uniqueCertificateSerialNumberIndex}" id="allowcertserialnumberoverride"
				value="#{certProfileBean.certificateProfile.allowCertSerialNumberOverride}"/>
			<h:outputLabel rendered="#{certProfileBean.uniqueCertificateSerialNumberIndex}" for="allowcertserialnumberoverride" value="#{web.text.ALLOW} "/>
			<h:outputText styleClass="help" rendered="#{!certProfileBean.uniqueCertificateSerialNumberIndex}" value="#{web.text.CERTSERIALNOUNIQUEIX}"/>
		</h:panelGroup>

		<h:panelGroup>
			<h:outputLabel for="checkallowdnoverridegroup" value="#{web.text.ALLOWDNOVERRIDE}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Allow%20subject%20DN%20override") %>
		</h:panelGroup>
		<h:panelGroup id="checkallowdnoverridegroup">
			<h:selectBooleanCheckbox id="checkallowdnoverride" value="#{certProfileBean.certificateProfile.allowDNOverride}"/>
			<h:outputLabel for="checkallowdnoverride" value="#{web.text.ALLOW} "/>
		</h:panelGroup>

		<h:outputLabel for="checkallowkeyusageoverridegroup" value="#{web.text.ALLOWKEYUSAGEOVERRIDE}"/>
		<h:panelGroup id="checkallowkeyusageoverridegroup">
			<h:selectBooleanCheckbox id="checkallowkeyusageoverride" value="#{certProfileBean.certificateProfile.allowKeyUsageOverride}"/>
			<h:outputLabel for="checkallowkeyusageoverride" value="#{web.text.ALLOW} "/>
		</h:panelGroup>

		<h:panelGroup>
			<h:outputLabel for="checkallowbackdatedrevokationgroup" value="#{web.text.ALLOWBACKDATEDREVOCATION}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Allow%20back%20dated%20revocation") %>
		</h:panelGroup>
		<h:panelGroup id="checkallowbackdatedrevokationgroup">
			<h:selectBooleanCheckbox id="checkallowbackdatedrevokation" value="#{certProfileBean.certificateProfile.allowBackdatedRevocation}"/>
			<h:outputLabel for="checkallowbackdatedrevokation" value="#{web.text.ALLOW} "/>
		</h:panelGroup>

	</h:panelGrid>
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- X.509v3 extensions (PKIX) --%>

		<h:outputLabel for="header_x509v3extensions" value="#{web.text.X509EXTENSIONS}" style="font-weight: bold;"/>
		<h:panelGroup id="header_x509v3extensions"/>

		<%-- PKIX Basic Constraints extension --%>

		<h:outputLabel for="cbbasicconstraintsgroup" value="#{web.text.EXT_PKIX_BASICCONSTRAINTS}"/>
		<h:panelGroup id="cbbasicconstraintsgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useBasicConstraints}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbbasicconstraints" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseBasicConstraints}"
				value="#{certProfileBean.certificateProfile.useBasicConstraints?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbbasicconstraints" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox id="cbbasicconstraintscritical" value="#{certProfileBean.certificateProfile.basicConstraintsCritical}"
				disabled="#{!certProfileBean.certificateProfile.useBasicConstraints}"/>
			<h:outputLabel for="cbbasicconstraintscritical" value="#{web.text.EXT_CRITICAL}"/>
		</h:panelGroup>

		<h:panelGroup rendered="#{certProfileBean.typeCA}">
			<h:outputLabel for="checkusepathlengthconstraintgroup" value="#{web.text.EXT_PKIX_BC_PATHLENGTH}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Path%20Length%20Constraints") %>
		</h:panelGroup>
		<h:panelGroup id="checkusepathlengthconstraintgroup" rendered="#{certProfileBean.typeCA}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.usePathLengthConstraint}" rendered="#{!web.legacyInternetExplorer}"
				disabled="#{!certProfileBean.certificateProfile.useBasicConstraints}"/>
			<h:commandButton id="checkusepathlengthconstraint" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUsePathLengthConstraint}"
				value="#{certProfileBean.certificateProfile.usePathLengthConstraint?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"
				disabled="#{!certProfileBean.certificateProfile.useBasicConstraints}"/>
			<h:outputLabel for="checkusepathlengthconstraint" value="#{web.text.ADD}…" styleClass="checkBoxOverlay"/>
			<h:outputLabel for="textfieldpathlengthconstraint" value="#{web.text.VALUE}"/>
			<h:inputText id="textfieldpathlengthconstraint" value="#{certProfileBean.certificateProfile.pathLengthConstraint}" size="2" maxlength="2"
				disabled="#{!certProfileBean.certificateProfile.usePathLengthConstraint || !certProfileBean.certificateProfile.useBasicConstraints}"
				title="#{web.text.FORMAT_INTEGER}" validatorMessage="#{web.text.ONLYDECNUMBERSINPATHLEN}" converterMessage="#{web.text.ONLYDECNUMBERSINPATHLEN}">
				<f:validateLength minimum="1" maximum="2"/>
				<f:validateLongRange minimum="0" maximum="99"/>
			</h:inputText>
		</h:panelGroup>

		<%-- PKIX Authority Key Identifier (AKI) extension --%>

		<h:outputLabel for="cbauthoritykeyidentifiergroup" value="#{web.text.EXT_PKIX_AUTHORITYKEYID}"/>
		<h:panelGroup id="cbauthoritykeyidentifiergroup">
			<h:selectBooleanCheckbox id="cbauthoritykeyidentifier" value="#{certProfileBean.certificateProfile.useAuthorityKeyIdentifier}"/>
			<h:outputLabel for="cbauthoritykeyidentifier" value="#{web.text.USE} "/>
		</h:panelGroup>

		<%-- PKIX Subject Key Identifier (SKI) extension --%>

		<h:outputLabel for="cbsubjectkeyidentifiergroup" value="#{web.text.EXT_PKIX_SUBJECTKEYID}"/>
		<h:panelGroup id="cbsubjectkeyidentifiergroup">
			<h:selectBooleanCheckbox id="cbsubjectkeyidentifier" value="#{certProfileBean.certificateProfile.useSubjectKeyIdentifier}"/>
			<h:outputLabel for="cbsubjectkeyidentifier" value="#{web.text.USE} "/>
		</h:panelGroup>

		<%-- PKIX Key Usage (KU) extension --%>

		<h:outputLabel for="cbkeyusagegroup" value="#{web.text.EXT_PKIX_KEYUSAGE}" style="font-weight: bold;"/>
		<h:panelGrid columns="1">
			<h:panelGroup id="cbkeyusagegroup">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useKeyUsage}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="cbkeyusage" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseKeyUsage}"
					value="#{certProfileBean.certificateProfile.useKeyUsage?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="cbkeyusage" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
				<h:selectBooleanCheckbox id="cbkeyusagecritical" value="#{certProfileBean.certificateProfile.keyUsageCritical}"
					disabled="#{!certProfileBean.certificateProfile.useKeyUsage}"/>
				<h:outputLabel for="cbkeyusagecritical" value="#{web.text.EXT_CRITICAL}"/>
			</h:panelGroup>
			<h:outputLabel for="keyUsageSelection" value="#{web.text.EXT_PKIX_KEYUSAGE}:" rendered="#{certProfileBean.certificateProfile.useKeyUsage}"/>
			<h:panelGrid id="keyUsageSelection" columns="6" rendered="#{certProfileBean.certificateProfile.useKeyUsage}">
				<h:selectBooleanCheckbox id="keyUsageDigitalSignature" value="#{certProfileBean.keyUsageDigitalSignature}"/>
				<h:outputLabel for="keyUsageDigitalSignature" value="#{web.text.KU_DIGITALSIGNATURE}"/>
				<h:selectBooleanCheckbox id="keyUsageDataEncipherment" value="#{certProfileBean.keyUsageDataEncipherment}"/>
				<h:outputLabel for="keyUsageDataEncipherment" value="#{web.text.KU_DATAENCIPHERMENT}"/>
				<h:selectBooleanCheckbox id="keyUsageKeyCrlSign" value="#{certProfileBean.keyUsageKeyCrlSign}"/>
				<h:outputLabel for="keyUsageKeyCrlSign" value="#{web.text.KU_CRLSIGN}"/>

				<h:selectBooleanCheckbox id="keyUsageNonRepudiation" value="#{certProfileBean.keyUsageNonRepudiation}"/>
				<h:outputLabel for="keyUsageNonRepudiation" value="#{web.text.KU_NONREPUDIATION}"/>
				<h:selectBooleanCheckbox id="keyUsageKeyAgreement" value="#{certProfileBean.keyUsageKeyAgreement}"/>
				<h:outputLabel for="keyUsageKeyAgreement" value="#{web.text.KU_KEYAGREEMENT}"/>
				<h:selectBooleanCheckbox id="keyUsageEncipherOnly" value="#{certProfileBean.keyUsageEncipherOnly}"/>
				<h:outputLabel for="keyUsageEncipherOnly" value="#{web.text.KU_ENCIPHERONLY}"/>

				<h:selectBooleanCheckbox id="keyUsageKeyEncipherment" value="#{certProfileBean.keyUsageKeyEncipherment}"/>
				<h:outputLabel for="keyUsageKeyEncipherment" value="#{web.text.KU_KEYENCIPHERMENT}"/>
				<h:selectBooleanCheckbox id="keyUsageKeyCertSign" value="#{certProfileBean.keyUsageKeyCertSign}"/>
				<h:outputLabel for="keyUsageKeyCertSign" value="#{web.text.KU_KEYCERTSIGN}"/>
				<h:selectBooleanCheckbox id="keyUsageDecipherOnly" value="#{certProfileBean.keyUsageDecipherOnly}"/>
				<h:outputLabel for="keyUsageDecipherOnly" value="#{web.text.KU_DECIPHERONLY}"/>
			</h:panelGrid>
		</h:panelGrid>

		<%-- PKIX Extended Key Usage (EKU) extension --%>

		<h:panelGroup>
			<h:outputLabel for="checkuseextendedkeyusagegroup" value="#{web.text.EXT_PKIX_EXTENDEDKEYUSAGE}" style="font-weight: bold;"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Extended%20Key%20Usage") %>
		</h:panelGroup>
		<h:panelGrid columns="1">
			<h:panelGroup id="checkuseextendedkeyusagegroup">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useExtendedKeyUsage}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="checkuseextendedkeyusage" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseExtendedKeyUsage}"
					value="#{certProfileBean.certificateProfile.useExtendedKeyUsage?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="checkuseextendedkeyusage" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
				<h:selectBooleanCheckbox id="cbextendedkeyusagecritical" value="#{certProfileBean.certificateProfile.extendedKeyUsageCritical}"
					disabled="#{!certProfileBean.certificateProfile.useExtendedKeyUsage}"/>
				<h:outputLabel for="cbextendedkeyusagecritical" value="#{web.text.EXT_CRITICAL}"/>
			</h:panelGroup>
			<h:selectManyListbox id="selectextendedkeyusage" value="#{certProfileBean.certificateProfile.extendedKeyUsageOids}" size="10"
				rendered="#{certProfileBean.certificateProfile.useExtendedKeyUsage}">
				<f:selectItems value="#{certProfileBean.extendedKeyUsageOidsAvailable}"/>
			</h:selectManyListbox>
		</h:panelGrid>

		<%-- PKIX Subject Alternative Name (SAN) extension --%>

		<h:outputLabel for="cbsubjectalternativenamegroup" value="#{web.text.EXT_PKIX_SUBJECTALTNAME}"/>
		<h:panelGroup id="cbsubjectalternativenamegroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useSubjectAlternativeName}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbsubjectalternativename" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseSubjectAlternativeName}"
				value="#{certProfileBean.certificateProfile.useSubjectAlternativeName?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbsubjectalternativename" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox id="cbsubjectalternativenamecritical" value="#{certProfileBean.certificateProfile.subjectAlternativeNameCritical}"
				disabled="#{!certProfileBean.certificateProfile.useSubjectAlternativeName}"/>
			<h:outputLabel for="cbsubjectalternativenamecritical" value="#{web.text.EXT_CRITICAL}"/>
		</h:panelGroup>

		<%-- PKIX Issuer Alternative Name (IAN) extension --%>

		<h:panelGroup>
			<h:outputLabel for="cbissueralternativenamegroup" value="#{web.text.EXT_PKIX_ISSUERALTNAME}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Issuer%20Alternative%20Name") %>
		</h:panelGroup>
		<h:panelGroup id="cbissueralternativenamegroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useIssuerAlternativeName}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbissueralternativename" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseIssuerAlternativeName}"
				value="#{certProfileBean.certificateProfile.useIssuerAlternativeName?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbissueralternativename" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox id="cbissueralternativenamecritical" value="#{certProfileBean.certificateProfile.issuerAlternativeNameCritical}"
				disabled="#{!certProfileBean.certificateProfile.useIssuerAlternativeName}"/>
			<h:outputLabel for="cbissueralternativenamecritical" value="#{web.text.EXT_CRITICAL}"/>
		</h:panelGroup>

		<%-- PKIX Subject Directory Attributes (SDA) extension --%>

		<h:outputLabel for="checksubjectdirattributesgroup" value="#{web.text.EXT_PKIX_SUBJECTDIRATTRS}"/>
		<h:panelGroup id="checksubjectdirattributesgroup">
			<h:selectBooleanCheckbox id="checksubjectdirattributes" value="#{certProfileBean.certificateProfile.useSubjectDirAttributes}"/>
			<h:outputLabel for="checksubjectdirattributes" value="#{web.text.USE} "/>
		</h:panelGroup>

		<%-- PKIX Name Constraints extension --%>

        <h:panelGroup>
    		<h:outputLabel for="checknameconstraintsgroup" value="#{web.text.EXT_PKIX_NAMECONSTRAINTS}"/>
    		<%= ejbcawebbean.getHelpReference("/userguide.html#Name%20Constraints") %>
		</h:panelGroup>
		<h:panelGroup id="checknameconstraintsgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useNameConstraints}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checknameconstraints" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseNameConstraints}"
				value="#{certProfileBean.certificateProfile.useNameConstraints?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checknameconstraints" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox id="checknameconstraintscritical" value="#{certProfileBean.certificateProfile.nameConstraintsCritical}"
				disabled="#{!certProfileBean.certificateProfile.useNameConstraints}"/>
			<h:outputLabel for="checknameconstraintscritical" value="#{web.text.EXT_CRITICAL}"/>
		</h:panelGroup>

	</h:panelGrid>
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- PKIX CRL Distribution Points (CRL-DP) extension --%>

		<h:outputLabel for="header_crls" value="#{web.text.EXT_PKIX_CRLDIST}" style="font-weight: bold;"/>
		<h:panelGroup id="header_crls"/>

		<h:panelGroup>
			<h:outputLabel for="cbcrldistributionpointgroup" value="#{web.text.EXT_PKIX_CRLDISTRIBPOINTS}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#CRL%20Distribution%20Points") %>
		</h:panelGroup>
		<h:panelGroup id="cbcrldistributionpointgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useCRLDistributionPoint}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbcrldistributionpoint" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseCRLDistributionPoint}"
				value="#{certProfileBean.certificateProfile.useCRLDistributionPoint?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbcrldistributionpoint" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox id="cbcrldistributionpointcritical" value="#{certProfileBean.certificateProfile.CRLDistributionPointCritical}"
				disabled="#{!certProfileBean.certificateProfile.useCRLDistributionPoint}"/>
			<h:outputLabel for="cbcrldistributionpointcritical" value="#{web.text.EXT_CRITICAL}"/>
		</h:panelGroup>

		<h:outputLabel for="cbusedefaultcrldistributionpointgroup" value="#{web.text.EXT_PKIX_CDP_CADEFINED}" rendered="#{certProfileBean.certificateProfile.useCRLDistributionPoint}" styleClass="subItem"/>
		<h:panelGroup id="cbusedefaultcrldistributionpointgroup" rendered="#{certProfileBean.certificateProfile.useCRLDistributionPoint}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useDefaultCRLDistributionPoint}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbusedefaultcrldistributionpoint" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseDefaultCRLDistributionPoint}"
				value="#{certProfileBean.certificateProfile.useDefaultCRLDistributionPoint?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbusedefaultcrldistributionpoint" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
		</h:panelGroup>

		<h:outputLabel for="textfieldcrldisturi" value="#{web.text.EXT_PKIX_CDP_URI}" rendered="#{certProfileBean.certificateProfile.useCRLDistributionPoint}" styleClass="subItem"/>
		<h:inputText id="textfieldcrldisturi" value="#{certProfileBean.certificateProfile.CRLDistributionPointURI}" size="60" maxlength="4096"
			rendered="#{certProfileBean.certificateProfile.useCRLDistributionPoint}"
			disabled="#{certProfileBean.certificateProfile.useDefaultCRLDistributionPoint}" title="#{web.text.FORMAT_URI}"/>

		<h:panelGroup rendered="#{certProfileBean.certificateProfile.useCRLDistributionPoint}">
			<h:outputLabel for="textfieldcrlissuer" value="#{web.text.EXT_PKIX_CDP_CRLISSUER}" styleClass="subItem"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#CRL%20Issuer") %>
		</h:panelGroup>
		<h:inputText id="textfieldcrlissuer" value="#{certProfileBean.certificateProfile.CRLIssuer}" size="60" maxlength="255" rendered="#{certProfileBean.certificateProfile.useCRLDistributionPoint}"
			disabled="#{certProfileBean.certificateProfile.useDefaultCRLDistributionPoint}" title="#{web.text.FORMAT_DN}"/>

		<%-- PKIX Freshest CRL extension --%>

		<h:panelGroup>
			<h:outputLabel for="cbusefreshestcrlgroup" value="#{web.text.EXT_PKIX_FRESHESTCRL}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Freshest%20CRL") %>
		</h:panelGroup>
		<h:panelGroup id="cbusefreshestcrlgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useFreshestCRL}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbusefreshestcrl" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseFreshestCRL}"
				value="#{certProfileBean.certificateProfile.useFreshestCRL?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbusefreshestcrl" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
		</h:panelGroup>

		<h:outputLabel for="cbusecadefinedfreshestcrlgroup" value="#{web.text.EXT_PKIX_FCRL_CADEFINED}" rendered="#{certProfileBean.certificateProfile.useFreshestCRL}" styleClass="subItem"/>
		<h:panelGroup id="cbusecadefinedfreshestcrlgroup" rendered="#{certProfileBean.certificateProfile.useFreshestCRL}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useCADefinedFreshestCRL}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbusecadefinedfreshestcrl" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseCADefinedFreshestCRL}"
				value="#{certProfileBean.certificateProfile.useCADefinedFreshestCRL?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbusecadefinedfreshestcrl" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
		</h:panelGroup>

		<h:outputLabel for="textfieldfreshestcrluri" value="#{web.text.EXT_PKIX_FCRL_URI}" rendered="#{certProfileBean.certificateProfile.useFreshestCRL}" styleClass="subItem"/>
		<h:inputText id="textfieldfreshestcrluri" value="#{certProfileBean.certificateProfile.freshestCRLURI}" size="45" maxlength="255" rendered="#{certProfileBean.certificateProfile.useFreshestCRL}"
			disabled="#{certProfileBean.certificateProfile.useCADefinedFreshestCRL}" title="#{web.text.FORMAT_URI}"/>

		<%-- PKIX Certificate Policies extension --%>

		<h:outputLabel for="certificatePolicies" value="#{web.text.EXT_PKIX_CERTIFICATEPOLICIES}" style="font-weight: bold;"/>
		<h:panelGrid id="certificatePolicies" columns="1">
			<h:panelGroup>
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useCertificatePolicies}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="checkusecertificatepolicies" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseCertificatePolicies}"
					value="#{certProfileBean.certificateProfile.useCertificatePolicies?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="checkusecertificatepolicies" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
				<h:selectBooleanCheckbox id="checkcertificatepoliciescritical" value="#{certProfileBean.certificateProfile.certificatePoliciesCritical}"
					disabled="#{!certProfileBean.certificateProfile.useCertificatePolicies}"/>
				<h:outputLabel for="checkcertificatepoliciescritical" value="#{web.text.EXT_CRITICAL}"/>
			</h:panelGroup>
			<h:dataTable value="#{certProfileBean.certificatePolicies}" var="certificatePolicy" rendered="#{certProfileBean.certificateProfile.useCertificatePolicies}">
				<h:column>
					<h:panelGrid columns="1">
						<h:outputLabel for="policyid" value="#{web.text.EXT_PKIX_CP_POLICYID}:"/>
						<h:outputLabel for="policynoticeunotice" value="#{web.text.EXT_PKIX_CP_USERNOTICE} (#{certificatePolicy.qualifierId}):" styleClass="subItem"
							rendered="#{certProfileBean.currentCertificatePolicyQualifierIdUserNotice}"/>
						<h:outputLabel for="policynoticedcpsurl" value="#{web.text.EXT_PKIX_CP_CPSURI} (#{certificatePolicy.qualifierId}):" styleClass="subItem"
							rendered="#{certProfileBean.currentCertificatePolicyQualifierIdCpsUri}"/>
					</h:panelGrid>
					<f:facet name="footer">
						<h:panelGrid columns="1">
							<h:outputLabel for="textfieldcertificatepolicyid" value="#{web.text.EXT_PKIX_CP_POLICYID}:"/>
						</h:panelGrid>
					</f:facet>
				</h:column>
				<h:column>
					<h:panelGrid columns="1">
						<h:outputText id="policyid" value="#{certificatePolicy.policyID}"/>
						<h:outputText id="policynoticeunotice" value="#{certificatePolicy.qualifier}" rendered="#{certProfileBean.currentCertificatePolicyQualifierIdUserNotice}"/>
						<h:outputText id="policynoticedcpsurl" value="#{certificatePolicy.qualifier}" rendered="#{certProfileBean.currentCertificatePolicyQualifierIdCpsUri}"/>
					</h:panelGrid>
					<f:facet name="footer">
						<h:panelGrid columns="1">
							<h:inputText id="textfieldcertificatepolicyid" value="#{certProfileBean.newCertificatePolicy.policyID}" size="20" maxlength="255" title="#{web.text.FORMAT_OID}"/>
							<h:panelGrid id="policyqualidinput" columns="3">
								<h:commandButton value="#{certProfileBean.newCertificatePolicyQualifierIdNone?'✓':' '}#{web.text.EXT_PKIX_CP_NOQUAL}"
									action="#{certProfileBean.actionNewCertificatePolicyQualifierIdNone}" disabled="#{certProfileBean.newCertificatePolicyQualifierIdNone}"
									title="#{web.text.EXT_PKIX_CP_POLICYQUALID}"/>
								<h:commandButton value="#{certProfileBean.newCertificatePolicyQualifierIdUserNotice?'✓':' '}#{web.text.EXT_PKIX_CP_USERNOTICE}"
									action="#{certProfileBean.actionNewCertificatePolicyQualifierIdUserNotice}" disabled="#{certProfileBean.newCertificatePolicyQualifierIdUserNotice}"
									title="#{web.text.EXT_PKIX_CP_POLICYQUALID}"/>
								<h:commandButton value="#{certProfileBean.newCertificatePolicyQualifierIdCpsUri?'✓':' '}#{web.text.EXT_PKIX_CP_CPSURI}"
									action="#{certProfileBean.actionNewCertificatePolicyQualifierIdCpsUri}" disabled="#{certProfileBean.newCertificatePolicyQualifierIdCpsUri}"
									title="#{web.text.EXT_PKIX_CP_POLICYQUALID}"/>
							</h:panelGrid>
							<h:inputText id="textareapolicynoticeunotice" rendered="#{certProfileBean.newCertificatePolicyQualifierIdUserNotice}"
								value="#{certProfileBean.newCertificatePolicy.qualifier}" size="45" maxlength="255" title="#{web.text.FORMAT_STRING}"/>
							<h:inputText id="textfielpolicynoticedcpsurl" rendered="#{certProfileBean.newCertificatePolicyQualifierIdCpsUri}"
								value="#{certProfileBean.newCertificatePolicy.qualifier}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"/>
						</h:panelGrid>
					</f:facet>
				</h:column>
				<h:column>
					<h:commandButton id="buttondeletepolicy" value="#{web.text.DELETE}" action="#{certProfileBean.deleteCertificatePolicy}"/>
					<f:facet name="footer">
						<h:commandButton id="buttonaddpolicy" value="#{web.text.ADD}" action="#{certProfileBean.addCertificatePolicy}"/>
					</f:facet>
				</h:column>
			</h:dataTable>
		</h:panelGrid>

		<%-- PKIX Authority Information Access (AIA) extension --%>

		<h:outputLabel for="checkuseauthorityinformationaccessgroup" value="#{web.text.EXT_PKIX_AUTHORITYINFOACCESS}" style="font-weight: bold;"/>
		<h:panelGroup id="checkuseauthorityinformationaccessgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkuseauthorityinformationaccess" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseAuthorityInformationAccess}"
				value="#{certProfileBean.certificateProfile.useAuthorityInformationAccess?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkuseauthorityinformationaccess" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
		</h:panelGroup>

		<%-- OCSP service locator part of Authority Information Access (AIA) extension --%>

		<h:outputLabel for="checkusedefaultocspservicelocatorgroup" value="#{web.text.EXT_PKIX_AIA_OCSP_CADEFINED}" rendered="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}"
			 styleClass="subItem"/>
		<h:panelGroup id="checkusedefaultocspservicelocatorgroup" rendered="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useDefaultOCSPServiceLocator}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkusedefaultocspservicelocator" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseDefaultOCSPServiceLocator}"
				value="#{certProfileBean.certificateProfile.useDefaultOCSPServiceLocator?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkusedefaultocspservicelocator" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
		</h:panelGroup>

		<h:panelGroup rendered="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}">
			<h:outputLabel for="textfieldocspservicelocatoruri" value="#{web.text.EXT_PKIX_AIA_OCSP_URI}" styleClass="subItem"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#OCSP%20Service%20Locator") %>
		</h:panelGroup>
		<h:inputText id="textfieldocspservicelocatoruri" value="#{certProfileBean.certificateProfile.OCSPServiceLocatorURI}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"
			 rendered="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}" disabled="#{certProfileBean.certificateProfile.useDefaultOCSPServiceLocator}"/>

		<%-- caIssuers part of Authority Information Access (AIA) extension --%>

		<h:outputLabel for="caIssuers" value="#{web.text.EXT_PKIX_AIA_CAISSUERS_URI}" rendered="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}"
			 styleClass="subItem"/>
		<h:dataTable id="caIssuers" value="#{certProfileBean.caIssuers}" var="caIssuer" rendered="#{certProfileBean.certificateProfile.useAuthorityInformationAccess}">
			<h:column>
				<h:outputText value="#{caIssuer}"/>
				<f:facet name="footer">
					<h:inputText id="textfieldcaissueruri" value="#{certProfileBean.newCaIssuer}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"/>
				</f:facet>
			</h:column>
			<h:column>
				<h:commandButton id="buttondeletecaissueruri" value="#{web.text.DELETE}" action="#{certProfileBean.deleteCaIssuer}" />
				<f:facet name="footer">
					<h:commandButton id="buttonaddcaissueruri" value="#{web.text.ADD}" action="#{certProfileBean.addCaIssuer}"/>
				</f:facet>
			</h:column>
		</h:dataTable>

		<%-- PKIX Private Key Usage Period extension --%>

		<h:panelGroup>
			<h:outputLabel for="privateKeyUsagePeriodGroup" value="#{web.text.EXT_PKIX_PRIVKEYUSAGEPERIOD}"/>
			<%=ejbcawebbean.getHelpReference("/userguide.html#Private%20Key%20Usage%20Period")%>
		</h:panelGroup>
		<h:panelGrid columns="3" id="privateKeyUsagePeriodGroup">
			<h:panelGroup>
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.usePrivateKeyUsagePeriodNotBefore}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="cbuseprivkeyusageperiodnotbefore" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUsePrivateKeyUsagePeriodNotBefore}"
					value="#{certProfileBean.certificateProfile.usePrivateKeyUsagePeriodNotBefore?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="cbuseprivkeyusageperiodnotbefore" value="#{web.text.EXT_PKIX_PKUP_STARTOFFSET}…" styleClass="checkBoxOverlay"/>
			</h:panelGroup>
			<h:inputText id="textfieldprivkeyusageperiodstartoffset" value="#{certProfileBean.privateKeyUsagePeriodStartOffset}" size="20" maxlength="255"
				disabled="#{!certProfileBean.certificateProfile.usePrivateKeyUsagePeriodNotBefore}"/>
			<h:outputText styleClass="help" value="#{web.text.FORMAT_TIME_YMD}"/>
			
			<h:panelGroup>
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.usePrivateKeyUsagePeriodNotAfter}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="cbuseprivkeyusageperiodnotafter" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUsePrivateKeyUsagePeriodNotAfter}"
					value="#{certProfileBean.certificateProfile.usePrivateKeyUsagePeriodNotAfter?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="cbuseprivkeyusageperiodnotafter" value="#{web.text.EXT_PKIX_PKUP_PERIODLENGTH}…" styleClass="checkBoxOverlay"/>
			</h:panelGroup>
			<h:inputText id="textfieldprivkeyusageperiodlength" value="#{certProfileBean.privateKeyUsagePeriodLength}" size="20" maxlength="255"
				disabled="#{!certProfileBean.certificateProfile.usePrivateKeyUsagePeriodNotAfter}"/>
			<h:outputText styleClass="help" value="#{web.text.FORMAT_TIME_YMD}"/>
		</h:panelGrid>

	</h:panelGrid>
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- Qualified Certificates Statements (qcStatements) extension --%>

		<h:outputLabel for="header_qcStatements" value="#{web.text.EXT_HEADER_QCSTATEMENTS}" style="font-weight: bold;"/>
		<h:panelGroup id="header_qcStatements"/>

		<h:outputLabel for="checkuseqcstatementgroup" value="#{web.text.EXT_PKIX_QCSTATEMENTS}"/>
		<h:panelGroup id="checkuseqcstatementgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useQCStatement}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkuseqcstatement" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseQCStatement}"
				value="#{certProfileBean.certificateProfile.useQCStatement?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkuseqcstatement" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox id="checkqcstatementcritical" value="#{certProfileBean.certificateProfile.QCStatementCritical}" disabled="#{!certProfileBean.certificateProfile.useQCStatement}"/>
			<h:outputLabel for="checkqcstatementcritical" value="#{web.text.EXT_CRITICAL}"/>
		</h:panelGroup>
	
		<h:outputLabel for="checkpkixqcsyntaxv2group" value="#{web.text.EXT_PKIX_QCS_PKIXQCSYNTAXV2}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:panelGroup id="checkpkixqcsyntaxv2group" rendered="#{certProfileBean.certificateProfile.useQCStatement}">
			<h:selectBooleanCheckbox id="checkpkixqcsyntaxv2" value="#{certProfileBean.certificateProfile.usePkixQCSyntaxV2}"/>
			<h:outputLabel for="checkpkixqcsyntaxv2" value="#{web.text.USE}"/>
		</h:panelGroup>

		<h:outputLabel for="textfieldqcsemanticsid" value="#{web.text.EXT_PKIX_QCS_SEMANTICSID}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:inputText id="textfieldqcsemanticsid" value="#{certProfileBean.certificateProfile.QCSemanticsId}" size="20" maxlength="255" title="#{web.text.FORMAT_OID}"
			 rendered="#{certProfileBean.certificateProfile.useQCStatement}"/>

		<h:outputLabel for="textfieldqcstatementraname" value="#{web.text.EXT_PKIX_QCS_NAMERA}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:inputText id="textfieldqcstatementraname" value="#{certProfileBean.certificateProfile.QCStatementRAName}" size="45" maxlength="255" title="#{web.text.FORMAT_STRING}"
			 rendered="#{certProfileBean.certificateProfile.useQCStatement}"/>

		<h:outputLabel for="checkqcetsiqcompliancegroup" value="#{web.text.EXT_ETSI_QCS_QCCOMPLIANCE}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:panelGroup id="checkqcetsiqcompliancegroup" rendered="#{certProfileBean.certificateProfile.useQCStatement}">
			<h:selectBooleanCheckbox id="checkqcetsiqcompliance" value="#{certProfileBean.certificateProfile.useQCEtsiQCCompliance}"/>
			<h:outputLabel for="checkqcetsiqcompliance" value="#{web.text.USE}"/>
		</h:panelGroup>

		<h:outputLabel for="checkqcetsisignaturedevicegroup" value="#{web.text.EXT_ETSI_QCS_SSCD}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:panelGroup id="checkqcetsisignaturedevicegroup" rendered="#{certProfileBean.certificateProfile.useQCStatement}">
			<h:selectBooleanCheckbox id="checkqcetsisignaturedevice" value="#{certProfileBean.certificateProfile.useQCEtsiSignatureDevice}"/>
			<h:outputLabel for="checkqcetsisignaturedevice" value="#{web.text.USE}"/>
		</h:panelGroup>

		<h:outputLabel for="qcetsivaluelimitgroup" value="#{web.text.EXT_ETSI_QCS_VALUELIMIT}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:panelGroup id="qcetsivaluelimitgroup" rendered="#{certProfileBean.certificateProfile.useQCStatement}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useQCEtsiValueLimit}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkqcetsivaluelimit" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseQCEtsiValueLimit}"
				value="#{certProfileBean.certificateProfile.useQCEtsiValueLimit?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkqcetsivaluelimit" value="#{web.text.ADD}…" styleClass="checkBoxOverlay"/>
			<h:outputLabel for="textfieldqcetsivaluelimitcur" value="#{web.text.EXT_ETSI_QCS_VL_CURRENCY} "/>
			<h:inputText id="textfieldqcetsivaluelimitcur" value="#{certProfileBean.certificateProfile.QCEtsiValueLimitCurrency}" size="3" maxlength="3" title="#{web.text.FORMAT_ISO4217}"
				disabled="#{!certProfileBean.certificateProfile.useQCEtsiValueLimit}" style="text-align: center;"/>
			<h:outputLabel for="textfieldqcetsivaluelimit" value=" #{web.text.EXT_ETSI_QCS_VL_AMOUNT} "/>
			<h:inputText id="textfieldqcetsivaluelimit" value="#{certProfileBean.certificateProfile.QCEtsiValueLimit}" size="3" maxlength="6" title="#{web.text.FORMAT_INTEGER}"
				disabled="#{!certProfileBean.certificateProfile.useQCEtsiValueLimit}" converterMessage="#{web.text.ONLYDECINETSIVALUELIMIT}" validatorMessage="#{web.text.ONLYDECINETSIVALUELIMIT}">
				<f:validateLength minimum="1" maximum="6"/>
				<f:validateLongRange minimum="0" maximum="999999"/>
			</h:inputText>
			<h:outputLabel for="textfieldqcetsivaluelimitexp" value="×10^ #{web.text.EXT_ETSI_QCS_VL_EXPONENT} "/>
			<h:inputText id="textfieldqcetsivaluelimitexp" value="#{certProfileBean.certificateProfile.QCEtsiValueLimitExp}" size="2" maxlength="2" title="#{web.text.FORMAT_INTEGER}"
				disabled="#{!certProfileBean.certificateProfile.useQCEtsiValueLimit}" converterMessage="#{web.text.ONLYDECINETSIVALUELIMIT}" validatorMessage="#{web.text.ONLYDECINETSIVALUELIMIT}">
				<f:validateLength minimum="1" maximum="2"/>
				<f:validateLongRange minimum="0" maximum="99"/>
			</h:inputText>
		</h:panelGroup>

		<h:outputLabel for="qcetsiretentionperiodgroup" value="#{web.text.EXT_ETSI_QCS_RETENTIONPERIOD}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:panelGroup id="qcetsiretentionperiodgroup" rendered="#{certProfileBean.certificateProfile.useQCStatement}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useQCEtsiRetentionPeriod}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkqcetsiretentionperiod" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseQCEtsiRetentionPeriod}"
				value="#{certProfileBean.certificateProfile.useQCEtsiRetentionPeriod?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkqcetsiretentionperiod" value="#{web.text.ADD}…" styleClass="checkBoxOverlay"/>
			<h:outputLabel for="textfieldqcetsiretentionperiod" value="#{web.text.VALUE} #{web.text.UNIT_YEARS} "/>
			<h:inputText id="textfieldqcetsiretentionperiod" value="#{certProfileBean.certificateProfile.QCEtsiRetentionPeriod}" size="2" maxlength="3" title="#{web.text.FORMAT_INTEGER}"
				disabled="#{!certProfileBean.certificateProfile.useQCEtsiRetentionPeriod}">
				<f:validateLength minimum="1" maximum="3"/>
				<f:validateLongRange minimum="0" maximum="999"/>
			</h:inputText>
		</h:panelGroup>

		<h:outputLabel for="checkqccustomstringgroup" value="#{web.text.EXT_PKIX_QCS_CUSTOMSTRING}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:panelGroup id="checkqccustomstringgroup" rendered="#{certProfileBean.certificateProfile.useQCStatement}">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useQCCustomString}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkqccustomstring" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseQCCustomString}"
				value="#{certProfileBean.certificateProfile.useQCCustomString?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkqccustomstring" value="#{web.text.ADD}…" styleClass="checkBoxOverlay"/>
			<h:outputLabel for="textfieldqccustomstringoid" value="#{web.text.EXT_PKIX_QCS_CUSTOMSTR_OID}"/>
			<h:inputText id="textfieldqccustomstringoid" value="#{certProfileBean.certificateProfile.QCCustomStringOid}" size="20" maxlength="255" title="#{web.text.FORMAT_OID}"
				disabled="#{!certProfileBean.certificateProfile.useQCCustomString}"/>
		</h:panelGroup>

		<h:outputLabel for="textfieldqccustomstringtext" value="#{web.text.EXT_PKIX_QCS_CUSTOMSTR_TEXT}" rendered="#{certProfileBean.certificateProfile.useQCStatement}" styleClass="subItem"/>
		<h:inputText id="textfieldqccustomstringtext" value="#{certProfileBean.certificateProfile.QCCustomStringText}" rendered="#{certProfileBean.certificateProfile.useQCStatement}"
			size="45" maxlength="255" title="#{web.text.FORMAT_STRING}"
			disabled="#{!certProfileBean.certificateProfile.useQCCustomString}"/>
	</h:panelGrid>

	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2"
		 rendered="#{certProfileBean.ctAvailable}">

		<%-- Certificate Transparency --%>

		<h:outputLabel for="header_certificatetransparency" value="#{web.text.EXT_HEADER_CERTIFICATETRANSPARENCY}" style="font-weight: bold;"/>
		<h:panelGroup id="header_certificatetransparency"/>

		<h:panelGroup>
			<h:outputLabel for="cbusecertificatetransparencyingroup" value="#{web.text.EXT_CERTIFICATE_TRANSPARENCY}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Certificate%20Transparency%20(Enterprise%20only)") %>
		</h:panelGroup>
		<h:panelGroup id="cbusecertificatetransparencyingroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useCertificateTransparencyInCerts}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbusecertificatetransparencyincerts" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseCertificateTransparencyInCerts}"
				value="#{certProfileBean.certificateProfile.useCertificateTransparencyInCerts?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbusecertificatetransparencyincerts" value="#{web.text.EXT_CT_USE_IN_CERTS}…" styleClass="checkBoxOverlay"/>
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useCertificateTransparencyInOCSP}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="cbusecertificatetransparencyinocsp" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseCertificateTransparencyInOCSP}"
				value="#{certProfileBean.certificateProfile.useCertificateTransparencyInOCSP?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="cbusecertificatetransparencyinocsp" value="#{web.text.EXT_CT_USE_IN_OCSP}…" styleClass="checkBoxOverlay"/>
		</h:panelGroup>

		<%-- Enabled CT logs selection --%>
		<h:outputLabel rendered="#{certProfileBean.ctEnabled}" for="selectctlogs" value="#{web.text.EXT_CT_ENABLEDLOGS}" styleClass="subItem"/>
		<h:selectManyListbox rendered="#{certProfileBean.ctEnabled}" id="selectctlogs" value="#{certProfileBean.enabledCTLogs}"
			size="#{certProfileBean.enabledCTLogsAvailableSize}" style="min-width: 280px;">
			<f:selectItems value="#{certProfileBean.enabledCTLogsAvailable}"/>
		</h:selectManyListbox>

		<h:outputLabel rendered="#{certProfileBean.ctEnabled}" for="textfieldctminscts" value="#{web.text.EXT_CT_MINSCTS}" styleClass="subItem"/>
		<h:inputText rendered="#{certProfileBean.ctEnabled}" id="textfieldctminscts" value="#{certProfileBean.certificateProfile.CTMinSCTs}" size="8" maxlength="255" title="#{web.text.FORMAT_INTEGER}"
			disabled="#{!certProfileBean.certificateProfile.useCertificateTransparencyInCerts && !certProfileBean.certificateProfile.useCertificateTransparencyInOCSP}"/>

		<h:outputLabel rendered="#{certProfileBean.ctEnabled}" for="textfieldctmaxscts" value="#{web.text.EXT_CT_MAXSCTS}" styleClass="subItem"/>
		<h:inputText rendered="#{certProfileBean.ctEnabled}" id="textfieldctmaxscts" value="#{certProfileBean.certificateProfile.CTMaxSCTs}" size="8" maxlength="255" title="#{web.text.FORMAT_INTEGER}"
			disabled="#{!certProfileBean.certificateProfile.useCertificateTransparencyInCerts && !certProfileBean.certificateProfile.useCertificateTransparencyInOCSP}"/>

		<h:outputLabel rendered="#{certProfileBean.ctEnabled}" for="textfieldctmaxretries" value="#{web.text.EXT_CT_MAXRETRIES}" styleClass="subItem"/>
		<h:inputText rendered="#{certProfileBean.ctEnabled}" id="textfieldctmaxretries" value="#{certProfileBean.certificateProfile.CTMaxRetries}" size="8" maxlength="255" title="#{web.text.FORMAT_INTEGER}"
			disabled="#{!certProfileBean.certificateProfile.useCertificateTransparencyInCerts && !certProfileBean.certificateProfile.useCertificateTransparencyInOCSP}"/>
	</h:panelGrid>

	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- Other extensions --%>
		<h:outputLabel for="otherextensions" value="#{web.text.OTHEREXTENSIONS}" style="font-weight: bold;"/>
		<h:panelGroup id="otherextensions"/>

		<%-- OCSP No Check extension --%>
		<h:outputLabel for="checkuseocspnocheckgroup" value="#{web.text.EXT_PKIX_OCSPNOCHECK}"/>
		<h:panelGroup id="checkuseocspnocheckgroup">
			<h:selectBooleanCheckbox id="checkuseocspnocheck" value="#{certProfileBean.certificateProfile.useOcspNoCheck}"/>
			<h:outputLabel for="checkuseocspnocheck" value="#{web.text.USE}"/>
		</h:panelGroup>

		<%-- MS Template extension --%>
		<h:outputLabel for="checkusemstemplategroup" value="#{web.text.EXT_MS_TEMPLATENAME}"/>
		<h:panelGroup id="checkusemstemplategroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useMicrosoftTemplate}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkusemstemplate" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseMicrosoftTemplate}"
				value="#{certProfileBean.certificateProfile.useMicrosoftTemplate?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkusemstemplate" value="#{web.text.ADD}…" styleClass="checkBoxOverlay"/>
			<h:outputLabel for="selectmstemplate" value="#{web.text.VALUE}: "/>
			<h:selectOneMenu id="selectmstemplate" value="#{certProfileBean.certificateProfile.microsoftTemplate}" disabled="#{!certProfileBean.certificateProfile.useMicrosoftTemplate}">
				<f:selectItems value="#{certProfileBean.microsoftTemplateAvailable}"/>
			</h:selectOneMenu>
			<h:outputText styleClass="help" value=" #{web.text.EXT_MS_TEMPLATENAME_HELP}"/>
		</h:panelGroup>

		<%-- SEIS Card Number extension --%>
		<h:panelGroup rendered="#{!certProfileBean.typeCA}">
			<h:outputLabel for="checkusecardnumbergroup" value="#{web.text.EXT_SEIS_CARDNUMBER}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Cardnumber") %>
		</h:panelGroup>
		<h:panelGroup id="checkusecardnumbergroup" rendered="#{!certProfileBean.typeCA}">
			<h:selectBooleanCheckbox id="checkusecardnumber" value="#{certProfileBean.certificateProfile.useCardNumber}"/>
			<h:outputLabel for="checkusecardnumber" value="#{web.text.USE}"/>
		</h:panelGroup>

	</h:panelGrid>
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- ePassport --%>

		<h:outputLabel for="cvc_epassport" value="#{web.text.CVCEPASSPORT}" style="font-weight: bold;"/>
		<h:panelGroup id="cvc_epassport"/>

		<%-- ICAO Document Type List (DTL) extension --%>
		<h:panelGroup>
			<h:outputLabel for="cbdocumenttypegroup" value="#{web.text.EXT_ICAO_DOCUMENTTYPELIST}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Document%20Type%20List") %>
		</h:panelGroup>
		<h:panelGrid columns="1">
			<h:panelGroup id="cbdocumenttypegroup">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useDocumentTypeList}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="cbusedocumenttype" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseDocumentTypeList}"
					value="#{certProfileBean.certificateProfile.useDocumentTypeList?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="cbusedocumenttype" value="#{web.text.USE}…" styleClass="checkBoxOverlay"/>
				<h:selectBooleanCheckbox id="cbdocumenttypecritical" value="#{certProfileBean.certificateProfile.documentTypeListCritical}" disabled="#{!certProfileBean.certificateProfile.useDocumentTypeList}"/>
				<h:outputLabel for="cbdocumenttypecritical" value="#{web.text.EXT_CRITICAL}"/>
			</h:panelGroup>
			<h:dataTable id="textfielddocumenttype" value="#{certProfileBean.documentTypeList}" var="current" rendered="#{certProfileBean.certificateProfile.useDocumentTypeList}">
				<h:column>
					<h:outputText value="#{current}"/>
					<f:facet name="footer">
						<h:inputText value="#{certProfileBean.documentTypeListNew}" size="45" maxlength="4096"/>
					</f:facet>
				</h:column>
				<h:column>
					<h:commandButton value="#{web.text.REMOVE}" action="#{certProfileBean.documentTypeListRemove}"/>
					<f:facet name="footer">
						<h:commandButton value="#{web.text.ADD}" action="#{certProfileBean.documentTypeListAdd}"/>
					</f:facet>
				</h:column>
			</h:dataTable>
		</h:panelGrid>

		<%-- CVC (ePassport) --%>
		<h:outputLabel for="selectcvctermtype" value="#{web.text.CVCTERMTYPE}" rendered="#{certProfileBean.cvcAvailable}"/>
		<h:panelGroup id="selectcvctermtype" rendered="#{certProfileBean.cvcAvailable}">
			<h:commandButton value="#{certProfileBean.cvcTerminalTypeIs?'✓':' '}#{web.text.CVCINSPECTIONSYSTEM}" disabled="#{certProfileBean.cvcTerminalTypeIs}" action="#{certProfileBean.setCvcTerminalTypeIs}"/>
			<h:commandButton value="#{certProfileBean.cvcTerminalTypeAt?'✓':' '}#{web.text.CVCAUTHENTICATIONTERMINAL}" disabled="#{certProfileBean.cvcTerminalTypeAt}" action="#{certProfileBean.setCvcTerminalTypeAt}"/>
			<h:commandButton value="#{certProfileBean.cvcTerminalTypeSt?'✓':' '}#{web.text.CVCSIGNATURETERMINAL}" disabled="#{certProfileBean.cvcTerminalTypeSt}" action="#{certProfileBean.setCvcTerminalTypeSt}"/>
		</h:panelGroup>

		<h:outputLabel for="selectcvcsigntermdvtype" value="#{web.text.CVCSIGNTERMDVTYPE}" rendered="#{certProfileBean.cvcAvailable && certProfileBean.cvcTerminalTypeSt}" styleClass="subItem"/>
		<h:selectOneMenu id="selectcvcsigntermdvtype" value="#{certProfileBean.certificateProfile.CVCSignTermDVType}" rendered="#{certProfileBean.cvcAvailable && certProfileBean.cvcTerminalTypeSt}" converter="javax.faces.Integer">
			<f:selectItems value="#{certProfileBean.cvcSignTermDVTypeAvailable}"/>
		</h:selectOneMenu>

		<h:panelGroup rendered="#{certProfileBean.cvcAvailable}">
			<h:outputLabel for="selectcvcaccessrights" value="#{web.text.CVCACCESSRIGHTS} " styleClass="subItem"/>
			<h:outputLabel rendered="#{certProfileBean.cvcTerminalTypeIs}" value="(#{web.text.CVCINSPECTIONSYSTEM})"/>
			<h:outputLabel for="selectcvcaccessrights_at" rendered="#{certProfileBean.cvcTerminalTypeAt}" value="(#{web.text.CVCAUTHENTICATIONTERMINAL})"/>
			<h:outputLabel for="selectcvcaccessrights_st" rendered="#{certProfileBean.cvcTerminalTypeSt}" value="(#{web.text.CVCSIGNATURETERMINAL})"/>
		</h:panelGroup>
		<h:panelGroup id="selectcvcaccessrights" rendered="#{certProfileBean.cvcAvailable}">
			<h:panelGrid columns="4" rendered="#{certProfileBean.cvcTerminalTypeIs}">
				<h:selectBooleanCheckbox id="cvcAccessRightDg3" value="#{certProfileBean.cvcAccessRightDg3}"/>
				<h:outputLabel for="cvcAccessRightDg3" value="#{web.text.CVCACCESSDG3}"/>
				<h:selectBooleanCheckbox id="cvcAccessRightDg4" value="#{certProfileBean.cvcAccessRightDg4}"/>
				<h:outputLabel for="cvcAccessRightDg4" value="#{web.text.CVCACCESSDG4}"/>
			</h:panelGrid>
			<h:selectManyListbox id="selectcvcaccessrights_at" rendered="#{certProfileBean.cvcTerminalTypeAt}" enabledClass="cvcoption_at"
				 value="#{certProfileBean.cvcLongAccessRights}" size="8" converter="javax.faces.Integer">
				<f:selectItems value="#{certProfileBean.cvcAccessRightsAtAvailable}"/>
			</h:selectManyListbox>
			<h:panelGrid  id="selectcvcaccessrights_st" columns="4" rendered="#{certProfileBean.cvcTerminalTypeSt}">
				<h:selectBooleanCheckbox id="cvcAccessRightSign" value="#{certProfileBean.cvcAccessRightSign}"/>
				<h:outputLabel for="cvcAccessRightSign" value="#{web.text.CVCACCESSSIGN}"/>
				<h:selectBooleanCheckbox id="cvcAccessRightQualSign" value="#{certProfileBean.cvcAccessRightQualSign}"/>
				<h:outputLabel for="cvcAccessRightQualSign" value="#{web.text.CVCACCESSQUALSIGN}"/>
			</h:panelGrid>
		</h:panelGroup>

	</h:panelGrid>
	<h:panelGrid columns="2" styleClass="edit" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- Other data --%>

		<h:outputLabel for="otherdata" value="#{web.text.OTHERDATA}" style="font-weight: bold;"/>
		<h:panelGroup id="otherdata"/>
		
		<h:panelGroup>
			<h:outputLabel for="checkuseldapdnordergroup" value="#{web.text.CERT_SUBJECTDN_LDAPORDER}" style="font-weight: bold;"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Use%20LDAP%20DN%20order") %>
		</h:panelGroup>
		<h:panelGroup id="checkuseldapdnordergroup">
			<h:selectBooleanCheckbox id="checkuseldapdnorder" value="#{certProfileBean.certificateProfile.useLdapDnOrder}"/>
			<h:outputLabel for="checkuseldapdnorder" value="#{web.text.USE}"/>
		</h:panelGroup>


		<h:outputLabel for="cnpostfixgroup" value="#{web.text.CERT_SUBJECTDN_CNPOSTFIX}"/>
		<h:panelGroup id="cnpostfixgroup">
			<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useCNPostfix}" rendered="#{!web.legacyInternetExplorer}"/>
			<h:commandButton id="checkusecnpostfix" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseCNPostfix}"
				value="#{certProfileBean.certificateProfile.useCNPostfix?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			<h:outputLabel for="checkusecnpostfix" value="#{web.text.ADD}…" styleClass="checkBoxOverlay"/>
			<h:outputText value="#{web.text.VALUE}: "/>
			<h:inputText id="textfieldcnpostfix" size="20" maxlength="255" title="#{web.text.FORMAT_STRING}" value="#{certProfileBean.certificateProfile.CNPostfix}"
				disabled="#{!certProfileBean.certificateProfile.useCNPostfix}"/>
			<h:outputText styleClass="help" value=" #{web.text.CERT_SUBJECTDN_CNPF_HELP}"/>
		</h:panelGroup>


		<h:panelGroup>
			<h:outputLabel for="checkusesubjectdnsubsetgroup" value="#{web.text.CERT_SUBJECTDN_SUBSET}"/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#Subset%20of%20Subject%20DN") %>
		</h:panelGroup>
		<h:panelGrid columns="1">
			<h:panelGroup id="checkusesubjectdnsubsetgroup">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useSubjectDNSubSet}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="checkusesubjectdnsubset" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseSubjectDNSubSet}"
					value="#{certProfileBean.certificateProfile.useSubjectDNSubSet?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="checkusesubjectdnsubset" value="#{web.text.RESTRICT}…" styleClass="checkBoxOverlay"/>
			</h:panelGroup>
			<h:selectManyListbox rendered="#{certProfileBean.certificateProfile.useSubjectDNSubSet}"
				id="selectsubjectdnsubset" value="#{certProfileBean.certificateProfile.subjectDNSubSet}" size="10">
				<f:selectItems value="#{certProfileBean.subjectDNSubSetAvailable}"/>
			</h:selectManyListbox>
		</h:panelGrid>

		<h:outputLabel for="checkusesubjectaltnamesubsetgroup" value="#{web.text.EXT_PKIX_SAN_SUBSET}"/>
		<h:panelGrid columns="1">
			<h:panelGroup id="checkusesubjectaltnamesubsetgroup">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{certProfileBean.certificateProfile.useSubjectAltNameSubSet}" rendered="#{!web.legacyInternetExplorer}"/>
				<h:commandButton id="checkusesubjectaltnamesubset" styleClass="checkBoxOverlay" action="#{certProfileBean.toggleUseSubjectAltNameSubSet}"
					value="#{certProfileBean.certificateProfile.useSubjectAltNameSubSet?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
				<h:outputLabel for="checkusesubjectaltnamesubset" value="#{web.text.RESTRICT}…" styleClass="checkBoxOverlay"/>
			</h:panelGroup>
			<h:selectManyListbox rendered="#{certProfileBean.certificateProfile.useSubjectAltNameSubSet}"
				id="selectsubjectaltnamesubset" value="#{certProfileBean.certificateProfile.subjectAltNameSubSet}" size="6" converter="javax.faces.Integer">
				<f:selectItems value="#{certProfileBean.subjectAltNameSubSetAvailable}"/>
			</h:selectManyListbox>
		</h:panelGrid>

		<h:outputLabel rendered="#{!empty certProfileBean.availableCertificateExtensionsAvailable}" for="selectusedcertificateextensions"
			value="#{web.text.USEDCERTEXTENSIONS}"/>
		<h:selectManyListbox rendered="#{!empty certProfileBean.availableCertificateExtensionsAvailable}" id="selectusedcertificateextensions"
			value="#{certProfileBean.certificateProfile.usedCertificateExtensions}" size="#{certProfileBean.availableCertificateExtensionsAvailableSize}" converter="javax.faces.Integer">
			<f:selectItems value="#{certProfileBean.availableCertificateExtensionsAvailable}"/>
		</h:selectManyListbox>

		<h:outputLabel for="selectavailablecas" value="#{web.text.AVAILABLECAS}"/>
		<h:selectManyListbox id="selectavailablecas" value="#{certProfileBean.certificateProfile.availableCAs}" size="#{certProfileBean.availableCAsAvailableSize}"
			converter="javax.faces.Integer" style="min-width: 280px;">
			<f:selectItems value="#{certProfileBean.availableCAsAvailable}"/>
		</h:selectManyListbox>
		
		<h:outputLabel rendered="#{certProfileBean.typeEndEntity}" for="selectavailablepublishers" value="#{web.text.PUBLISHERS}"/>
		<h:selectManyListbox rendered="#{certProfileBean.typeEndEntity}" id="selectavailablepublishers" value="#{certProfileBean.certificateProfile.publisherList}"
			size="#{certProfileBean.publisherListAvailableSize}" converter="javax.faces.Integer" style="min-width: 280px;">
			<f:selectItems value="#{certProfileBean.publisherListAvailable}"/>
		</h:selectManyListbox>
		
		<h:outputLabel for="approvalSettings" value="#{web.text.APPROVALSETTINGS}"/>
		<h:panelGrid columns="1" id="approvalSettings">
			<h:panelGrid columns="4">
				<h:selectBooleanCheckbox id="approvalEnabledAddEndEntity" value="#{certProfileBean.approvalEnabledAddEndEntity}"/>
				<h:outputLabel for="approvalEnabledAddEndEntity" value="#{web.text.APPROVEADDEDITENDENTITY}"/>
				<h:selectBooleanCheckbox id="approvalEnabledKeyRecover" value="#{certProfileBean.approvalEnabledKeyRecover}"/>
				<h:outputLabel for="approvalEnabledKeyRecover" value="#{web.text.APPROVEKEYRECOVER}"/>
				<h:selectBooleanCheckbox id="approvalEnabledRevocation" value="#{certProfileBean.approvalEnabledRevocation}"/>
				<h:outputLabel for="approvalEnabledRevocation" value="#{web.text.APPROVEREVOCATION}"/>
				<h:selectBooleanCheckbox id="approvalEnabledActivateCa" value="#{certProfileBean.approvalEnabledActivateCa}"/>
				<h:outputLabel for="approvalEnabledActivateCa" value="#{web.text.APPROVEACTIVATECA}"/>
			</h:panelGrid>
			<h:panelGroup>
				<h:outputLabel for="selectnumofrequiredapprovals" value="#{web.text.NUMOFREQUIREDAPPROVALS}"/>
				<h:selectOneMenu id="selectnumofrequiredapprovals" value="#{certProfileBean.certificateProfile.numOfReqApprovals}" converter="javax.faces.Integer">
					<f:selectItems value="#{certProfileBean.numOfReqApprovalsAvailable}"/>
				</h:selectOneMenu>
			</h:panelGroup>
		</h:panelGrid>

		<h:panelGroup/>
		<h:panelGroup>
			<h:commandButton value="#{web.text.SAVE}" action="#{certProfileBean.save}"/>
			<h:commandButton value="#{web.text.CANCEL}" action="#{certProfileBean.cancel}"/>
		</h:panelGroup>

	</h:panelGrid>
</h:form>


<%
   String footurl=globalconfiguration.getFootBanner();%>
  <jsp:include page="<%=footurl%>"/>
</body>
</f:view>
</html>
