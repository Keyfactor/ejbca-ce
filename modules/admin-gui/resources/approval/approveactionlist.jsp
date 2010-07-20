<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,
                                           org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
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
<script type="text/javascript">
<!--
function viewcert(link){
    enclink = encodeURI(link);
    win_popup = window.open(enclink, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</script>

<f:view>
<body>

<h1><h:outputText value="#{web.text.APPROVEACTIONS}"/></h1>
<h:form>
<p align="center"><h:outputText value="#{web.text.SEARCHFORACTION}"/>  
<h:selectOneMenu id="status" value="#{listApproveActionSessionBean.selectedStatus}"> 
  <f:selectItems value="#{listApproveActionSessionBean.availableStatus}"/>
</h:selectOneMenu>
   <h:outputText value="#{web.text.REQUESTEDWITHIN}"/>    
  <h:selectOneMenu id="timespan" value="#{listApproveActionSessionBean.selectedTimeSpan}">
  <f:selectItems value="#{listApproveActionSessionBean.availableTimeSpans}"/>
</h:selectOneMenu>
  <h:commandButton id="list" action="#{listApproveActionSessionBean.list}" value="#{web.text.LIST}"/>
  </p>
</h:form>
  <h4 align="center"><h:messages  layout="table" errorClass="alert"/></h4>
  <hr/>
  <h:form >
    <p align="center">

    <h:panelGroup id="body" >
        <t:dataTable id="data"
                styleClass="Table"
                headerClass="standardTable_Header"
                footerClass="standardTable_Header"    
                rowClasses="#{listApproveActionSessionBean.rowClasses}"                       
                var="approveActionDataVOView"
                value="#{listApproveActionSessionBean.listData}"
                sortColumn="#{listApproveActionSessionBean.sort}"
                sortAscending="#{listApproveActionSessionBean.ascending}" 
                preserveDataModel="false"
                rows="#{web.entriesPerPage}"
                width="100%"
                 >
           <h:column>
               <f:facet name="header">
               <t:commandSortHeader  columnName="requestDate" arrow="false" >               
                 <h:outputText  value="#{web.text.REQUESTDATE}" />
               </t:commandSortHeader>               

               </f:facet>
               <h:outputText value="#{approveActionDataVOView.requestDate}" />
           </h:column>

           <h:column>
               <f:facet name="header">
               <t:commandSortHeader columnName="approveActionName" arrow="false" >               
                  <h:outputText value="#{web.text.APPROVEACTIONNAME}" />
               </t:commandSortHeader>
               </f:facet>
               <f:verbatim>
                 <h:commandLink immediate="true"  onmousedown='#{approveActionDataVOView.approveActionWindowLink}' >
                   <h:outputText value="#{approveActionDataVOView.approveActionName}" />    
                 </h:commandLink>          
               </f:verbatim>
           </h:column>

           <h:column>
               <f:facet name="header">
               <t:commandSortHeader columnName="requestUsername" arrow="false" > 
                  <h:outputText value="#{web.text.REQUESTINGADMIN}" />
               </t:commandSortHeader>
               </f:facet>
               <f:verbatim>
                 <h:commandLink immediate="true" onmousedown='#{approveActionDataVOView.viewRequestorCertLink}' rendered="#{approveActionDataVOView.showViewRequestorCertLink}">
                   <h:outputText value="#{approveActionDataVOView.requestAdminName}"/> 
                 </h:commandLink> 
                 <h:outputText value="#{approveActionDataVOView.requestAdminName}" rendered="#{!approveActionDataVOView.showViewRequestorCertLink}"/> 
               </f:verbatim>
           </h:column>
           <h:column>
               <f:facet name="header">
               <t:commandSortHeader columnName="status" arrow="false" > 
                  <h:outputText value="#{web.text.STATUS}" />
               </t:commandSortHeader>
               </f:facet>
               <h:outputText value="#{approveActionDataVOView.status}" />
           </h:column>

       </t:dataTable>
        <h:panelGrid columns="1" styleClass="scrollerTable2" >
       
            <t:dataScroller id="scroll_1"
                    for="data"
                    fastStep="10"
                    pageCountVar="pageCount"
                    pageIndexVar="pageIndex"
                    styleClass="scroller"
                    paginator="true"
                    paginatorMaxPages="9"
                    paginatorTableClass="paginator"
                    paginatorActiveColumnStyle="font-weight:bold;"
                    >
                <f:facet name="first" >
                    <h:graphicImage url="#{web.image['arrow-first.gif']}"  />
                </f:facet>
                <f:facet name="last">
                    <h:graphicImage url="#{web.image['arrow-last.gif']}" />
                </f:facet>
                <f:facet name="previous">
                    <h:graphicImage url="#{web.image['arrow-previous.gif']}"  />
                </f:facet>
                <f:facet name="next">
                    <h:graphicImage url="#{web.image['arrow-next.gif']}"  />
                </f:facet>
                <f:facet name="fastforward">
                    <h:graphicImage url="#{web.image['arrow-ff.gif']}"  />
                </f:facet>
                <f:facet name="fastrewind">
                    <h:graphicImage url="#{web.image['arrow-fr.gif']}"  />
                </f:facet>
            </t:dataScroller>
            <t:dataScroller id="scroll_2"
                    for="data"
                    rowsCountVar="rowsCount"
                    displayedRowsCountVar="displayedRowsCountVar"
                    firstRowIndexVar="firstRowIndex"
                    lastRowIndexVar="lastRowIndex"
                    pageCountVar="pageCount"
                    pageIndexVar="pageIndex"
                    >
                <h:outputText value="#{rowsCount}" /><f:verbatim> </f:verbatim><h:outputText value="#{web.text.APPROVALREQUESTSFOUND}" />    

            </t:dataScroller>    
            </h:panelGrid>   
          </h:panelGroup>         
    </p>
     </h:form>
       <hr/>

	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
   
	<jsp:include page="<%= footurl %>" />
  
</body>
</f:view>
</html>

