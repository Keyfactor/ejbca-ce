<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h"%>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f"%>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp"
	import="
org.ejbca.config.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,
org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper,
org.ejbca.core.model.authorization.AccessRulesConstants
"%>
<jsp:useBean id="ejbcawebbean" scope="session"
	class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" />
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
 helpbean.authorizedToApprovalPages();
%>
<html>
<head>
<title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
<base href="<%= ejbcawebbean.getBaseUrl() %>" />
<link rel="stylesheet" type="text/css"
	href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
<meta http-equiv="Content-Type"
	content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
<script type="text/javascript">
<!--
function viewcert(link){
    enclink = encodeURI(link);
    win_popup = window.open(enclink, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</script>
</head>

<f:view>
	<body>

		<h1>
			<h:outputText value="#{web.text.APPROVEACTIONS}" />
		</h1>

		<h:form>
			<p align="center">
				<h:outputText value="#{web.text.SEARCHFORACTION}" />
				&nbsp;
				<h:selectOneMenu id="status"
					value="#{listApproveActionManagedBean.selectedStatus}">
					<f:selectItems
						value="#{listApproveActionManagedBean.availableStatus}" />
				</h:selectOneMenu>
				<h:outputText value="#{web.text.REQUESTEDWITHIN}" />
				<h:selectOneMenu id="timespan"
					value="#{listApproveActionManagedBean.selectedTimeSpan}">
					<f:selectItems
						value="#{listApproveActionManagedBean.availableTimeSpans}" />
				</h:selectOneMenu>
				<h:outputText value=" " />
				<h:commandButton id="list"
					action="#{listApproveActionManagedBean.list}"
					value="#{web.text.SEARCH}" />
			</p>
		</h:form>

		<div class="message">
			<h:messages layout="table" errorClass="alert" />
		</div>
		<hr />
		<h:form>
			<p align="center">

				<h:panelGroup id="body">
					<t:dataTable id="data" styleClass="Table"
						headerClass="standardTable_Header"
						footerClass="standardTable_Header"
						rowClasses="#{listApproveActionManagedBean.rowClasses}"
						var="approveActionDataVOView"
						value="#{listApproveActionManagedBean.listData}"
						sortColumn="#{listApproveActionManagedBean.sort}"
						sortAscending="#{listApproveActionManagedBean.ascending}"
						preserveDataModel="false" rows="#{web.entriesPerPage}"
						width="100%">
						<h:column>
							<f:facet name="header">
								<t:commandSortHeader columnName="requestDate">
										<h:graphicImage url="#{web.image['uparrow.gif']}" rendered="#{listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByRequestDate}"/>
										<h:graphicImage url="#{web.image['downarrow.gif']}" rendered="#{!listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByRequestDate}"/>
									<h:outputText value="#{web.text.REQUESTDATE}" />
								</t:commandSortHeader>
							</f:facet>
							<h:outputText value="#{approveActionDataVOView.requestDate}" />
						</h:column>

						<h:column>
							<f:facet name="header">
								<t:commandSortHeader columnName="approveActionName">
									<h:graphicImage url="#{web.image['uparrow.gif']}" rendered="#{listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByApproveActionName}"/>
									<h:graphicImage url="#{web.image['downarrow.gif']}" rendered="#{!listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByApproveActionName}"/>
									<h:outputText value="#{web.text.APPROVEACTIONNAME}" />
								</t:commandSortHeader>
							</f:facet>
							<h:commandLink immediate="true"
								onmousedown='#{approveActionDataVOView.approveActionWindowLink}'>
								<h:outputText
									value="#{approveActionDataVOView.approveActionName}" />
							</h:commandLink>
						</h:column>

						<h:column>
							<f:facet name="header">
								<t:commandSortHeader columnName="requestUsername">
									<h:graphicImage url="#{web.image['uparrow.gif']}" rendered="#{listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByRequestUsername}"/>
									<h:graphicImage url="#{web.image['downarrow.gif']}" rendered="#{!listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByRequestUsername}"/>
									<h:outputText value="#{web.text.REQUESTINGADMIN}" />
								</t:commandSortHeader>
							</f:facet>
							<h:commandLink immediate="true"
								onmousedown='#{approveActionDataVOView.viewRequestorCertLink}'
								rendered="#{approveActionDataVOView.showViewRequestorCertLink}">
								<h:outputText
									value="#{approveActionDataVOView.requestAdminName}" />
							</h:commandLink>
							<h:outputText value="#{approveActionDataVOView.requestAdminName}"
								rendered="#{!approveActionDataVOView.showViewRequestorCertLink}" />
						</h:column>

						<t:column>
							<f:facet name="header">
								<t:commandSortHeader columnName="status">
									<h:outputText value="#{web.text.STATUS}" />
									<h:graphicImage url="#{web.image['uparrow.gif']}" rendered="#{listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByStatus}"/>
									<h:graphicImage url="#{web.image['downarrow.gif']}" rendered="#{!listApproveActionManagedBean.ascending and listApproveActionManagedBean.sortedByStatus}"/>
								</t:commandSortHeader>
							</f:facet>
							<h:outputText value="#{approveActionDataVOView.status}" />
						</t:column>
					</t:dataTable>

					<h:panelGrid columns="1" styleClass="scrollerTable2">

						<t:dataScroller id="scroll_1" for="data" fastStep="10"
							pageCountVar="pageCount" pageIndexVar="pageIndex"
							styleClass="scroller" paginator="true" paginatorMaxPages="9"
							paginatorTableClass="paginator"
							paginatorActiveColumnStyle="font-weight:bold;">
							<f:facet name="first">
								<h:graphicImage url="#{web.image['arrow-first.gif']}" />
							</f:facet>
							<f:facet name="last">
								<h:graphicImage url="#{web.image['arrow-last.gif']}" />
							</f:facet>
							<f:facet name="previous">
								<h:graphicImage url="#{web.image['arrow-previous.gif']}" />
							</f:facet>
							<f:facet name="next">
								<h:graphicImage url="#{web.image['arrow-next.gif']}" />
							</f:facet>
							<f:facet name="fastforward">
								<h:graphicImage url="#{web.image['arrow-ff.gif']}" />
							</f:facet>
							<f:facet name="fastrewind">
								<h:graphicImage url="#{web.image['arrow-fr.gif']}" />
							</f:facet>
						</t:dataScroller>
						<t:dataScroller id="scroll_2" for="data" rowsCountVar="rowsCount"
							displayedRowsCountVar="displayedRowsCountVar"
							firstRowIndexVar="firstRowIndex" lastRowIndexVar="lastRowIndex"
							pageCountVar="pageCount" pageIndexVar="pageIndex">
							<h:outputText value="#{rowsCount}" />
							<f:verbatim>
							</f:verbatim>
							<h:outputText value="#{web.text.APPROVALREQUESTSFOUND}" />
						</t:dataScroller>
					</h:panelGrid>
				</h:panelGroup>
			</p>
		</h:form>
		<hr />

		<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>

		<jsp:include page="<%= footurl %>" />

	</body>
</f:view>
</html>

