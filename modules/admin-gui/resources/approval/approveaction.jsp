<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
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
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>

<f:view>
<body onload='resize()'>

<script type="text/javascript">
<!--
function viewcert(link){
    enclink = encodeURI(link);
    win_popup = window.open(enclink, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</script>

<h2 align="center"><h:outputText value="#{web.text.APPROVEACTION}"/></h2>
<h:form>
  <h:inputHidden id="approveActionID" value="#{approvalActionRequest.uniqueId}"/>
  <f:attribute name="windowWidth" value="#{approvalActionSession.windowWidth}"/>

   <h3 align="center">
     <h:outputText value="#{approvalActionSession.approveRequestData.approveActionName}"/>
     <br /><h:messages  layout="table" errorClass="alert"/><br />
     <h:outputText value="#{web.text.CURRENTSTATUS}"/> <h:outputText value=" : "/> <h:outputText value="#{approvalActionSession.approveRequestData.status}"/><br />     
   </h3>
   <h4 align="center">
   	</h4>
   	<table border="0" cellpadding="5" width="100%">
   	   	<tr id="Row0">
   			<td><h:outputText value="#{web.text.REQUESTDATE}"/></td>
   			<td><h:outputText value="#{approvalActionSession.approveRequestData.requestDate}"/></td>
   		</tr>
   	   	<tr id="Row1">
   			<td><h:outputText value="#{web.text.EXPIREDATE}"/></td>
   			<td><h:outputText value="#{approvalActionSession.approveRequestData.expireDate}"/></td>
   		</tr>
   	   	<tr id="Row0">
   			<td><h:outputText value="#{web.text.REQUESTINGADMIN}"/></td>
   			<td><h:outputText value="#{approvalActionSession.approveRequestData.requestAdminName}"/></td>
   		</tr>
   	   	<tr id="Row1">
   			<td><h:outputText value="#{web.text.RELATEDCA}"/></td>
   			<td><h:outputText value="#{approvalActionSession.approveRequestData.caName}"/></td>
   		</tr>
   	   	<tr id="Row0">
   			<td><h:outputText value="#{web.text.RELATEDEEPROFILE}"/></td>
   			<td><h:outputText value="#{approvalActionSession.approveRequestData.endEntityProfileName}"/></td>
   		</tr>
   		<tr id="Row1">
   			<td><h:outputText value="#{web.text.REMAININGAPPROVALS}"/></td>
   			<td><h:outputText value="#{approvalActionSession.approveRequestData.remainingApprovals}"/></td>
   		</tr>
   	</table>

   

   <f:verbatim>
    <f:subview id="showcmp" rendered="#{approvalActionSession.approvalRequestComparable}">
      <h:dataTable value="#{approvalActionSession.approveRequestData.textComparisonList}" var="textCompareRow"  width="100%">
        <h:column>
          <f:facet name="header">
            <h:outputText value="#{web.text.ORIGINALACTIONDATA}"/>
          </f:facet>
          <h:outputText value="#{textCompareRow.orgvalue}"   styleClass="#{textCompareRow.textComparisonColor}"/>
        </h:column>
        <h:column>
          <f:facet name="header">
            <h:outputText value="#{web.text.REQUESTEDACTIONDATA}"/>
          </f:facet>
          <h:outputText value="#{textCompareRow.newvalue}" styleClass="#{textCompareRow.textComparisonColor}"/>
        </h:column>
      </h:dataTable>
     </f:subview>
     <f:subview id="shownoncmp" rendered="#{!approvalActionSession.approvalRequestComparable and !approvalActionSession.approveRequestData.containingLink}">
      <p align="center">
      <h:dataTable value="#{approvalActionSession.approveRequestData.textComparisonList}" var="singleTextCompareRow"  width="100%">
        <h:column>
          <f:facet name="header">
            <h:outputText value="#{web.text.REQUESTEDACTIONDATA}"/>
          </f:facet>
          <h:outputText value="#{singleTextCompareRow.newvalue}"/>
        </h:column>
      </h:dataTable>
      </p>
     </f:subview>
     <f:subview id="shownoncmpwithlinks" rendered="#{!approvalActionSession.approvalRequestComparable and approvalActionSession.approveRequestData.containingLink}">
      <p align="center">
      <h:dataTable value="#{approvalActionSession.approveRequestData.textListExceptLinks}" var="singleTextCompareRow"  width="100%">
        <h:column>
          <f:facet name="header">
            <h:outputText value="#{web.text.REQUESTEDACTIONDATA}"/>
          </f:facet>
          <h:outputText value="#{singleTextCompareRow.newvalue}"/>
        </h:column>
      </h:dataTable>
      <h:dataTable value="#{approvalActionSession.approveRequestData.approvalDataLinks}" var="link"  width="100%">
        <h:column>
          <h:outputText value="#{link.preDescription}"/>
          <h:outputLink value="#{link.URI}" target="Viewinfo" onclick="#{approvalView.viewApproverCertLink}">
            <h:outputText value="#{link.description}"/>
          </h:outputLink>
          <h:outputText value="#{link.postDescription}"/>
        </h:column>
      </h:dataTable>
      </p>
     </f:subview>
  </f:verbatim>
<br/>
<br/>
    <h3 align="center"><h:outputText value="#{web.text.APPROVEDBY}"/></h3>
 
  <h:dataTable id="approvalTable" value="#{approvalActionSession.approvalViews}" var="approvalView" width="100%">
    <h:column>
      <f:facet name="header">
        <h:panelGroup>
          <h:outputText value="#{web.text.ACTION}"/>
        </h:panelGroup>
      </f:facet>
      <h:outputText value="#{approvalView.adminAction}"/>
    </h:column>
    <h:column>
      <f:facet name="header">
        <h:outputText value="#{web.text.DATE}"/>
      </f:facet>
      <h:outputText value="#{approvalView.approvalDate}"/>
    </h:column>
    <h:column>
      <f:facet name="header">
        <h:outputText value="#{web.text.ADMINISTRATOR}"/>
      </f:facet>
          <h:outputLink value="" target="Viewinfo" onclick="#{approvalView.viewApproverCertLink}">
            <h:outputText  value="#{approvalView.approvalAdmin}"/>            
          </h:outputLink>         
    </h:column>
    <h:column>
      <f:facet name="header">
        <h:panelGroup>
          <h:outputText value="#{web.text.COMMENT}"/>
        </h:panelGroup>
      </f:facet>
      <h:outputText value="#{approvalView.comment}"/>
    </h:column>
  </h:dataTable>   
    <p align="center">
    <f:subview id="shownonerow" rendered="#{!approvalActionSession.existsApprovals}">
      <h3 align="center"><h:outputText value="#{web.text.NONE}"/></h3>
    </f:subview>    
    <br /><br /><br />       
      <f:subview id="showapprovebuttons" rendered="#{approvalActionSession.approvable}">
        <h:outputText value="#{web.text.COMMENT}"/><h:outputText value=":"/> 
        <h:inputTextarea id="comment" rows="2" cols="30" value="#{approvalActionSession.comment}"/><br />
        <h:commandButton  id="accept" value="#{web.text.APPROVE}" action="#{approvalActionSession.approve}" onclick="return confirmapprove()"/>
        <h:commandButton  id="reject" value="#{web.text.REJECT}" action="#{approvalActionSession.reject}" onclick="return confirmreject()"/>
       </f:subview>
      <h:commandButton  id="button" value="#{web.text.CLOSE}" onclick="self.close()"/>    
    </p>
 </h:form>

  <script language="javascript">
<!--
function resize(){
  window.resizeTo(<h:outputText value="#{approvalActionSession.windowWidth}"/>,800);
}
function confirmapprove(){
  return confirm('<h:outputText value="#{web.text.AREYOUSUREAPPROVE}"/>');
}
function confirmreject(){
  return confirm('<h:outputText value="#{web.text.AREYOUSUREREJECT}"/>'); 
}
-->
</script>
</body>
</f:view>
</html>

