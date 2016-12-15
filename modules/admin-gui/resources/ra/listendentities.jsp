<%@page import="org.ejbca.core.ejb.ra.NoSuchEndEntityException"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.cesecore.authorization.AuthorizationDeniedException,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.rainterface.UserView, org.ejbca.ui.web.admin.rainterface.SortBy,org.ejbca.ui.web.RevokedInfoView,org.ejbca.core.model.SecConst,
                 org.ejbca.ui.web.admin.rainterface.RAInterfaceBean, org.cesecore.certificates.endentity.EndEntityConstants,org.ejbca.core.model.ra.raadmin.AdminPreference, org.cesecore.certificates.util.DNFieldExtractor,
                 javax.ejb.CreateException, org.ejbca.util.query.*, java.util.*, org.ejbca.core.model.authorization.AccessRulesConstants" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />

<%! // Declarations

  static final String ACTION                             = "action";
  static final String ACTION_LISTUSERS                   = "listusers";
  static final String ACTION_CHANGEFILTERMODETO_BASIC    = "changefiltermodetobasic";
  static final String ACTION_CHANGEFILTERMODETO_ADVANCED = "changefiltermodetoadvanced";

  static final String USER_PARAMETER           = "username";
  static final String SUBJECTDN_PARAMETER      = "subjectdnparameter";

  static final String OLD_ACTION               = "oldaction";
  static final String OLD_ACTION_LISTUSERS     = "oldactionlistusers";
  static final String OLD_ACTION_FINDUSER      = "oldactionfinduser";
  static final String OLD_ACTION_FINDTOKEN     = "oldactionfindtoken";
  static final String OLD_ACTION_ISREVOKED     = "oldactionisrevoked";
  static final String OLD_ACTION_LISTEXPIRED   = "oldactionlistexpired";
  static final String OLD_ACTION_NOACTION      = "oldactionnoaction";  
  static final String OLD_ACTION_ADVANCEDLIST  = "oldactionadvancedlist";
  static final String OLD_ACTION_VALUE         = "oldactionvalue";

  static final String OLD_MATCHWITHROW1 = "oldmatchwithrow1";
  static final String OLD_MATCHWITHROW2 = "oldnmatchwithrow2";
  static final String OLD_MATCHWITHROW3 = "oldmatchwithrow3";
  static final String OLD_MATCHWITHROW4 = "oldmatchwithrow4";
  static final String OLD_MATCHTYPEROW1 = "oldmatchtyperow1";
  static final String OLD_MATCHTYPEROW2 = "oldmatchtyperow2";
  static final String OLD_MATCHTYPEROW3 = "oldmatchtyperow3";
  static final String OLD_MATCHVALUEROW1 = "oldmatchvaluerow1";
  static final String OLD_MATCHVALUEROW2 = "oldmatchvaluerow2";
  static final String OLD_MATCHVALUEROW3 = "oldmatchvaluerow3";
  static final String OLD_CONNECTORROW2  = "oldconnectorrow2";
  static final String OLD_CONNECTORROW3  = "oldconnectorrow3";
  static final String OLD_CONNECTORROW4  = "oldconnectorrow4";
  static final String OLD_DAY_ROW4       = "olddayrow4"; 
  static final String OLD_DAY_ROW5       = "olddayrow5"; 
  static final String OLD_MONTH_ROW4     = "oldmonthrow4"; 
  static final String OLD_MONTH_ROW5     = "oldmonthrow5"; 
  static final String OLD_YEAR_ROW4      = "oldyearrow4"; 
  static final String OLD_YEAR_ROW5      = "oldyearrow5"; 
  static final String OLD_TIME_ROW4      = "oldtimerow4";
  static final String OLD_TIME_ROW5      = "oldtimerow5";


  static final String BUTTON_DELETE_USERS        = "buttondeleteusers";
  static final String BUTTON_DELETEREVOKE_USERS  = "buttondeleterevokeusers";
//  static final String BUTTON_CHANGESTATUS      = "buttonchangestatus"; 
  static final String BUTTON_REVOKE_USERS      = "buttonrevokeusers";  
  static final String BUTTON_FIND              = "buttonfind";
  static final String BUTTON_LIST              = "buttonlist";
  static final String BUTTON_ISREVOKED         = "buttonisrevoked";
  static final String BUTTON_FINDTOKEN         = "buttonfindtoken";
  static final String BUTTON_LISTEXPIRED       = "buttonlistexpired";
  static final String BUTTON_RELOAD            = "buttonreload";
  static final String BUTTON_ADVANCEDLIST      = "buttonadvancedlist";

  static final String BUTTON_NEXT              = "buttonnext";
  static final String BUTTON_PREVIOUS          = "buttonprevious";
  static final String BUTTON_SELECTALL         = "buttonselectall";
  static final String BUTTON_DESELECTALL       = "buttondeselectall";
  static final String BUTTON_INVERTSELECTION   = "buttoninvertselection";

  static final String SORTBY_USERNAME_ACC           = "sortbyusernameaccending";
  static final String SORTBY_USERNAME_DEC           = "sortbyusernamedecending";
  static final String SORTBY_CA_ACC                 = "sortbycaaccending";
  static final String SORTBY_CA_DEC                 = "sortbycadecending";
  static final String SORTBY_COMMONNAME_ACC         = "sortbycommonnameaccending";
  static final String SORTBY_COMMONNAME_DEC         = "sortbycommonnamedecending";
  static final String SORTBY_ORGANIZATIONALUNIT_ACC = "sortbyorganizationalunitaccending";
  static final String SORTBY_ORGANIZATIONALUNIT_DEC = "sortbyorganizationalunitdecending";
  static final String SORTBY_ORGANIZATION_ACC       = "sortbyorganizationaccending";
  static final String SORTBY_ORGANIZATION_DEC       = "sortbyorganizationdecending";
  static final String SORTBY_STATUS_ACC             = "sortbystatusaccending";
  static final String SORTBY_STATUS_DEC             = "sortbystatusdecending";

  static final String SELECT_LIST_STATUS        = "selectliststatus";
//  static final String SELECT_CHANGE_STATUS      = "selectchangestatus"; 
  static final String SELECT_REVOKE_REASON      = "selectrevokereason"; 
  static final String SELECT_MATCHWITH_ROW1     = "selectmatchwithrow1"; 
  static final String SELECT_MATCHWITH_ROW2     = "selectmatchwithrow2"; 
  static final String SELECT_MATCHWITH_ROW3     = "selectmatchwithrow3"; 
  static final String SELECT_MATCHWITH_ROW4     = "selectmatchwithrow4"; 
  static final String SELECT_MATCHTYPE_ROW1     = "selectmatchtyperow1"; 
  static final String SELECT_MATCHTYPE_ROW2     = "selectmatchtyperow2"; 
  static final String SELECT_MATCHTYPE_ROW3     = "selectmatchtyperow3"; 
  static final String SELECT_MATCHVALUE_ROW1    = "selectmatchvaluerow1";
  static final String SELECT_MATCHVALUE_ROW2    = "selectmatchvaluerow2";
  static final String SELECT_MATCHVALUE_ROW3    = "selectmatchvaluerow3";
  static final String SELECT_CONNECTOR_ROW2     = "selectconnectorrow2"; 
  static final String SELECT_CONNECTOR_ROW3     = "selectconnectorrow3"; 
  static final String SELECT_CONNECTOR_ROW4     = "selectconnectorrow4"; 
  static final String SELECT_DAY_ROW4           = "selectdayrow4"; 
  static final String SELECT_DAY_ROW5           = "selectdayrow5"; 
  static final String SELECT_MONTH_ROW4         = "selectmonthrow4"; 
  static final String SELECT_MONTH_ROW5         = "selectmonthrow5"; 
  static final String SELECT_YEAR_ROW4          = "selectyearrow4"; 
  static final String SELECT_YEAR_ROW5          = "selectyearrow5"; 
  static final String SELECT_TIME_ROW4          = "selecttimerow4";
  static final String SELECT_TIME_ROW5          = "selecttimerow5";

  static final String CHECKBOX_SELECT_USER      = "checkboxselectuser";
  static final String CHECKBOX_VALUE            = "true";

  static final String TEXTFIELD_USERNAME         = "textfieldusername";
  static final String TEXTFIELD_SERIALNUMBER     = "textfieldserialnumber";
  static final String TEXTFIELD_TOKENSERIALNUMBER= "textfieldtokenserialnumber";
  static final String TEXTFIELD_DAYS             = "textfielddays";
  static final String TEXTFIELD_MATCHVALUE_ROW1  = "textfieldmatchvaluerow1";
  static final String TEXTFIELD_MATCHVALUE_ROW2  = "textfieldmatchvaluerow2";
  static final String TEXTFIELD_MATCHVALUE_ROW3  = "textfieldmatchvaluerow3";

  static final String HIDDEN_SORTBY             = "hiddensortby";
  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_RECORDNUMBER       = "hiddenrecordnumber"; 

  static final String VALUE_NONE                = "-1";
  static final int ALL_STATUS                   = -1;
%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_VIEWENDENTITY); 
                                            rabean.initialize(request, ejbcawebbean);
  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  
  final String VIEWUSER_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath() + "/viewendentity.jsp";
  final String EDITUSER_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath() + "/editendentity.jsp";
  final String VIEWHISTORY_LINK         = ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath() + "/viewhistory.jsp";
  final String VIEWTOKEN_LINK           = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "hardtoken/viewtoken.jsp";

  RequestHelper.setDefaultCharacterEncoding(request);

  String oldaction        = OLD_ACTION_NOACTION; 
  String oldactionvalue   = null;
  String oldmatchwithrow1 = request.getParameter(OLD_MATCHWITHROW1);
  String oldmatchwithrow2 = request.getParameter(OLD_MATCHWITHROW2);
  String oldmatchwithrow3 = request.getParameter(OLD_MATCHWITHROW3);
  String oldmatchwithrow4 = request.getParameter(OLD_MATCHWITHROW4);
  String oldmatchtyperow1 = request.getParameter(OLD_MATCHTYPEROW1);
  String oldmatchtyperow2 = request.getParameter(OLD_MATCHTYPEROW2);
  String oldmatchtyperow3 = request.getParameter(OLD_MATCHTYPEROW3);
  String oldmatchvaluerow1 = request.getParameter(OLD_MATCHVALUEROW1);
  String oldmatchvaluerow2 = request.getParameter(OLD_MATCHVALUEROW2);
  String oldmatchvaluerow3 = request.getParameter(OLD_MATCHVALUEROW3);
  String oldconnectorrow2 = request.getParameter(OLD_CONNECTORROW2);
  String oldconnectorrow3 = request.getParameter(OLD_CONNECTORROW3);
  String oldconnectorrow4 = request.getParameter(OLD_CONNECTORROW4);
  String olddayrow4 = request.getParameter(OLD_DAY_ROW4); 
  String olddayrow5 = request.getParameter(OLD_DAY_ROW5); 
  String oldmonthrow4 = request.getParameter(OLD_MONTH_ROW4);
  String oldmonthrow5 = request.getParameter(OLD_MONTH_ROW5);
  String oldyearrow4 = request.getParameter(OLD_YEAR_ROW4);
  String oldyearrow5 = request.getParameter(OLD_YEAR_ROW5);
  String oldtimerow4 = request.getParameter(OLD_TIME_ROW4);
  String oldtimerow5 = request.getParameter(OLD_TIME_ROW5);

  String sortby         = SORTBY_USERNAME_ACC;

  boolean blank                   = true;
  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/listendentities.jsp";
  UserView[] users                = null;
  int numcheckboxes               = 0;
  boolean editbuttonpressed       = false;

  boolean illegalquery            = false;
  boolean largeresult             = false;
  boolean notauthorizedrevokeall  = false; 
  boolean notauthorizeddeleteall  = false; 
  boolean notauthorizedchangeall  = false;
  boolean notfoundall             = false;
  boolean notapprovedall          = false;
  boolean waitingforapproval      = false;
  boolean alreadyrevoked          = false;
  boolean notremoveall            = false;

  int filtermode = ejbcawebbean.getLastFilterMode();

  String[] validOldActions = {OLD_ACTION, OLD_ACTION_LISTUSERS, OLD_ACTION_FINDUSER, OLD_ACTION_FINDTOKEN, OLD_ACTION_ISREVOKED, 
		  OLD_ACTION_LISTEXPIRED, OLD_ACTION_NOACTION, OLD_ACTION_ADVANCEDLIST, OLD_ACTION_VALUE};
  String[] validSortBys = {SORTBY_USERNAME_ACC, SORTBY_USERNAME_DEC, SORTBY_CA_ACC, SORTBY_CA_DEC, SORTBY_COMMONNAME_ACC, SORTBY_COMMONNAME_DEC,
		  SORTBY_ORGANIZATIONALUNIT_ACC, SORTBY_ORGANIZATIONALUNIT_DEC, SORTBY_ORGANIZATION_ACC, SORTBY_ORGANIZATION_DEC, SORTBY_STATUS_ACC, SORTBY_STATUS_DEC};

  // Determine action 
  int record   = 0;
  int size = ejbcawebbean.getEntriesPerPage();
 
  if (request.getParameter(HIDDEN_RECORDNUMBER) != null ){
    record =  Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER)); 
  } 

  if (request.getParameter(HIDDEN_SORTBY) != null ){
    //sortby =  request.getParameter(HIDDEN_SORTBY);
    sortby = ejbcawebbean.getCleanOption(request.getParameter(HIDDEN_SORTBY), validSortBys);
  } 

  if( request.getParameter(OLD_ACTION) != null){
    //oldaction = request.getParameter(OLD_ACTION);
      oldaction = ejbcawebbean.getCleanOption(request.getParameter(OLD_ACTION), validOldActions);
    if(request.getParameter(OLD_ACTION_VALUE) != null){
      oldactionvalue= request.getParameter(OLD_ACTION_VALUE);
    }
    

  }

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_CHANGEFILTERMODETO_ADVANCED)){
      ejbcawebbean.setLastFilterMode(AdminPreference.FILTERMODE_ADVANCED);
      filtermode = AdminPreference.FILTERMODE_ADVANCED;
    }
    if( request.getParameter(ACTION).equals(ACTION_CHANGEFILTERMODETO_BASIC)){
      ejbcawebbean.setLastFilterMode(AdminPreference.FILTERMODE_BASIC);
      filtermode = AdminPreference.FILTERMODE_BASIC;    
    }
    if( request.getParameter(ACTION).equals(ACTION_LISTUSERS)){
      blank=false;

      if( request.getParameter(BUTTON_DELETE_USERS) != null){
          // Delete selected users
          // TEMPORATE
       editbuttonpressed=true;
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.List indexes = new  java.util.ArrayList();
       int index;
       while(parameters.hasMoreElements()){
        String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_SELECT_USER) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_SELECT_USER.length())); //Without []
           indexes.add(Integer.valueOf(index));
         }
       }
       
       if(indexes.size() > 0){
         String[] usernames = new String[indexes.size()];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.get(i)).intValue();
           usernames[i] = java.net.URLDecoder.decode(request.getParameter(HIDDEN_USERNAME+index),"UTF-8");
         }
         notauthorizeddeleteall = !rabean.deleteUsers(usernames);
       }
      }
      if( request.getParameter(BUTTON_REVOKE_USERS) != null){
        // Check reasons.
        String reason = request.getParameter(SELECT_REVOKE_REASON);
        if(reason != null){

          // Revoke selected users
         editbuttonpressed=true;
         java.util.Enumeration parameters = request.getParameterNames();
         java.util.List indexes = new  java.util.ArrayList();
         int index;
         while(parameters.hasMoreElements()){
          String parameter = (String) parameters.nextElement();
           if(parameter.startsWith(CHECKBOX_SELECT_USER) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
             index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_SELECT_USER.length())); //Without []
             indexes.add(Integer.valueOf(index));
           }
         }
       
         if(indexes.size() > 0){
           String[] usernames = new String[indexes.size()];
           for(int i = 0; i < indexes.size(); i++){
             index = ((java.lang.Integer) indexes.get(i)).intValue();
             usernames[i] = java.net.URLDecoder.decode(request.getParameter(HIDDEN_USERNAME+index),"UTF-8");
             try {
             	rabean.revokeUser(usernames[i], Integer.parseInt(reason));
             } catch (AuthorizationDeniedException e) {
             	notauthorizedrevokeall = true;
             } catch (NoSuchEndEntityException e) {
             	notfoundall = true;
             } catch (org.ejbca.core.model.approval.ApprovalException e) {
             	notapprovedall = true;
             } catch (org.ejbca.core.model.approval.WaitingForApprovalException e) {
             	waitingforapproval = true;
             } catch (org.ejbca.core.model.ra.AlreadyRevokedException e) {
             	alreadyrevoked = true;
             }
           }
         }
        }
      }
      if( request.getParameter(BUTTON_DELETEREVOKE_USERS) != null){
        // Check reasons.
        String reason = request.getParameter(SELECT_REVOKE_REASON);
        if(reason != null){

          // Revoke selected users
         editbuttonpressed=true;
         java.util.Enumeration parameters = request.getParameterNames();
         java.util.List indexes = new  java.util.ArrayList();
         int index;
         while(parameters.hasMoreElements()){
          String parameter = (String) parameters.nextElement();
           if(parameter.startsWith(CHECKBOX_SELECT_USER) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
             index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_SELECT_USER.length())); //Without []
             indexes.add(Integer.valueOf(index));
           }
         }
       
         if(indexes.size() > 0){
           String[] usernames = new String[indexes.size()];
           for(int i = 0; i < indexes.size(); i++){
             index = ((java.lang.Integer) indexes.get(i)).intValue();
             usernames[i] = java.net.URLDecoder.decode(request.getParameter(HIDDEN_USERNAME+index),"UTF-8");
             try {
             	rabean.revokeAndDeleteUser(usernames[i], Integer.parseInt(reason));
             } catch (AuthorizationDeniedException e) {
             	notauthorizedrevokeall = true;
             	notauthorizeddeleteall = true;
             } catch (NoSuchEndEntityException e) {
             	notfoundall = true;
             } catch (javax.ejb.RemoveException e) {
             	notremoveall = true;
             } catch (org.ejbca.core.model.approval.ApprovalException e) {
             	notapprovedall = true;
             } catch (org.ejbca.core.model.approval.WaitingForApprovalException e) {
             	waitingforapproval = true;
             }
           }           
         }
        }
      }
    }
   }
 
   if( request.getParameter(SORTBY_USERNAME_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_USERNAME_ACC;
     rabean.sortUserData(SortBy.USERNAME,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_USERNAME_DEC+".x") != null ){
     // Sortby username decending
     sortby = SORTBY_USERNAME_DEC;
     rabean.sortUserData(SortBy.USERNAME,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_CA_ACC+".x") != null ){
     // Sortby CA accending
     sortby = SORTBY_CA_ACC;
     rabean.sortUserData(SortBy.CA,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_CA_DEC+".x") != null ){
     // Sortby username decending
     sortby = SORTBY_CA_DEC;
     rabean.sortUserData(SortBy.CA,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_COMMONNAME_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_COMMONNAME_ACC;
     rabean.sortUserData(SortBy.COMMONNAME,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_COMMONNAME_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_COMMONNAME_DEC;
     rabean.sortUserData(SortBy.COMMONNAME,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATIONALUNIT_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATIONALUNIT_ACC;
     rabean.sortUserData(SortBy.ORGANIZATIONALUNIT,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATIONALUNIT_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATIONALUNIT_DEC;
     rabean.sortUserData(SortBy.ORGANIZATIONALUNIT,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATION_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATION_ACC;
     rabean.sortUserData(SortBy.ORGANIZATION,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATION_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATION_DEC;
     rabean.sortUserData(SortBy.ORGANIZATION,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_STATUS_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_STATUS_ACC;
     rabean.sortUserData(SortBy.STATUS,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_STATUS_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_STATUS_DEC;
     rabean.sortUserData(SortBy.STATUS,SortBy.DECENDING);
   }

   if( request.getParameter(BUTTON_PREVIOUS) != null ){
     record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
     record -= ejbcawebbean.getEntriesPerPage();
     if(record < 0 ) record=0;
   }
   if( request.getParameter(BUTTON_NEXT) != null ){
     record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
     record += ejbcawebbean.getEntriesPerPage();
   }

   if( (editbuttonpressed || request.getParameter(BUTTON_RELOAD)!=null) && oldaction.equals(OLD_ACTION_FINDUSER) ){
        String user = oldactionvalue; 
       if(user != null){
         if(!user.trim().equals("")){
           users = rabean.filterByUsername(user);
         }
       }
     }else{
       if( (editbuttonpressed || request.getParameter(BUTTON_RELOAD)!=null) && oldaction.equals(OLD_ACTION_LISTUSERS) ){
         String status = oldactionvalue;
         if(status != null){
           if(!status.trim().equals("")){
               if(status.equals(Integer.toString(ALL_STATUS))){
                  users = rabean.findAllUsers(record,size);
               }
               else{
                 Query query = new Query(Query.TYPE_USERQUERY); 
                 query.add(UserMatch.MATCH_WITH_STATUS,BasicMatch.MATCH_TYPE_EQUALS,status);
                 users = rabean.filterByQuery(query,record,size, AccessRulesConstants.VIEW_END_ENTITY);
               }


         }
       }
     }else{
       if( (editbuttonpressed || request.getParameter(BUTTON_RELOAD)!=null)&& oldaction.equals(OLD_ACTION_ISREVOKED) ){
         String serialnumber = oldactionvalue;
         if(serialnumber != null){
           if(!serialnumber.trim().equals("")){
             users = rabean.filterByCertificateSerialNumber(serialnumber.trim(),record,size);
         }
       }
     }else{
       if( (editbuttonpressed || request.getParameter(BUTTON_RELOAD)!=null)&& oldaction.equals(OLD_ACTION_FINDTOKEN) ){
         String tokenserialnumber = oldactionvalue;
         if(tokenserialnumber != null){
           if(!tokenserialnumber.trim().equals("")){
             users = rabean.filterByTokenSN(tokenserialnumber.trim(),record,size);
         }
       }
     }else{
       if( (editbuttonpressed || request.getParameter(BUTTON_RELOAD)!=null) && oldaction.equals(OLD_ACTION_LISTEXPIRED) ){
         String days = oldactionvalue;
         if(days != null){
           if(!days.trim().equals("")){
             users = rabean.filterByExpiringCertificates(days.trim(),record,size);

         }
       }
     }else{
       if( (editbuttonpressed || request.getParameter(BUTTON_RELOAD)!=null) && oldaction.equals(OLD_ACTION_ADVANCEDLIST) ){

               int matchwithrow1 = (request.getParameter(OLD_MATCHWITHROW1)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHWITHROW1)));
               int matchwithrow2 = (request.getParameter(OLD_MATCHWITHROW2)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHWITHROW2)));
               int matchwithrow3 = (request.getParameter(OLD_MATCHWITHROW3)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHWITHROW3)));
               int matchwithrow4 = (request.getParameter(OLD_MATCHWITHROW4)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHWITHROW4)));
               int matchtyperow1 = (request.getParameter(OLD_MATCHTYPEROW1)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHTYPEROW1)));
               int matchtyperow2 = (request.getParameter(OLD_MATCHTYPEROW2)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHTYPEROW2)));
               int matchtyperow3 = (request.getParameter(OLD_MATCHTYPEROW3)==null?-1:Integer.parseInt(request.getParameter(OLD_MATCHTYPEROW3)));
               int connectorrow2 = (request.getParameter(OLD_CONNECTORROW2)==null?-1:Integer.parseInt(request.getParameter(OLD_CONNECTORROW2)));
               int connectorrow3 = (request.getParameter(OLD_CONNECTORROW3)==null?-1:Integer.parseInt(request.getParameter(OLD_CONNECTORROW3)));
               int connectorrow4 = (request.getParameter(OLD_CONNECTORROW4)==null?-1:Integer.parseInt(request.getParameter(OLD_CONNECTORROW4)));
               int dayrow4       = (request.getParameter(OLD_DAY_ROW4)==null?-1:Integer.parseInt(request.getParameter(OLD_DAY_ROW4)));
               int dayrow5       = (request.getParameter(OLD_DAY_ROW5)==null?-1:Integer.parseInt(request.getParameter(OLD_DAY_ROW5)));
               int monthrow4     = (request.getParameter(OLD_MONTH_ROW4)==null?-1:Integer.parseInt(request.getParameter(OLD_MONTH_ROW4)));
               int monthrow5     = (request.getParameter(OLD_MONTH_ROW5)==null?-1:Integer.parseInt(request.getParameter(OLD_MONTH_ROW5)));
               int yearrow4      = (request.getParameter(OLD_YEAR_ROW4)==null?-1:Integer.parseInt(request.getParameter(OLD_YEAR_ROW4)));
               int yearrow5      = (request.getParameter(OLD_YEAR_ROW5)==null?-1:Integer.parseInt(request.getParameter(OLD_YEAR_ROW5)));
               int timerow4      = (request.getParameter(OLD_TIME_ROW4)==null?-1:Integer.parseInt(request.getParameter(OLD_TIME_ROW4)));
               int timerow5      = (request.getParameter(OLD_TIME_ROW5)==null?-1:Integer.parseInt(request.getParameter(OLD_TIME_ROW5)));
               
               String matchvaluerow1 = request.getParameter(OLD_MATCHVALUEROW1);
               String matchvaluerow2 = request.getParameter(OLD_MATCHVALUEROW2);
               String matchvaluerow3 = request.getParameter(OLD_MATCHVALUEROW3);
               boolean matchadded = false; 
    
              Query query = new Query(Query.TYPE_USERQUERY);

              if(matchwithrow1 != -1 && matchtyperow1 != -1 && matchvaluerow1 != null){
                 if(!matchvaluerow1.trim().equals("")){
                   query.add(matchwithrow1,matchtyperow1, matchvaluerow1);
                   matchadded = true; 
                 } 
              }
              if(connectorrow2 != -1 && matchwithrow2 != -1 && matchtyperow2 != -1 && matchvaluerow2 != null){
                 if(!matchvaluerow2.trim().equals("")){
                   query.add(connectorrow2);
                   query.add(matchwithrow2,matchtyperow2, matchvaluerow2);
                   matchadded = true; 
                 } 
              }
              if(connectorrow3 != -1 && matchwithrow3 != -1 && matchtyperow3 != -1 && matchvaluerow3 != null){
                 if(!matchvaluerow3.trim().equals("")){
                   query.add(connectorrow3);
                   query.add(matchwithrow3,matchtyperow3, matchvaluerow3);
                   matchadded = true; 
                 } 
              }
              Date startdate = null;
              Date enddate = null;
              Calendar querytime = Calendar.getInstance();
              if( matchwithrow4 != -1 ){
                querytime.set(yearrow4, monthrow4, dayrow4+1, timerow4, 0 ,0); 
                startdate = querytime.getTime();
                querytime.set(yearrow5, monthrow5, dayrow5+1, timerow5, 0 ,0); 
                enddate = querytime.getTime();
              }

              if(connectorrow4 != -1 && matchwithrow4 != -1 ){
            	  if ( matchadded ) {
                      query.add(matchwithrow4, startdate, enddate, connectorrow4);
            	  } else {
                      query.add(matchwithrow4, startdate, enddate);
            	  }
              }

              if(query.isLegalQuery()){
                users = rabean.filterByQuery(query,record,size, AccessRulesConstants.VIEW_END_ENTITY);  
              }else{
                 illegalquery = true;
              } 

     }
     else{
       if( request.getParameter(BUTTON_FIND) != null){
         String username = request.getParameter(TEXTFIELD_USERNAME); 
         if(username != null){
           username=username.trim();
           if(!username.equals("")){
             record=0;
             users = rabean.filterByUsername(username);
             oldaction=OLD_ACTION_FINDUSER;
             oldactionvalue=username;
          }
        }
      }else{
         if( request.getParameter(BUTTON_LIST) != null){
           String status = request.getParameter(SELECT_LIST_STATUS); 
           if(status != null){
             status= status.trim();
             if(!status.equals("")){
               record=0;
               if(status.equals(Integer.toString(ALL_STATUS))){
                  users = rabean.findAllUsers(record,size);
               }
               else{
                 Query query = new Query(Query.TYPE_USERQUERY); 
                 query.add(UserMatch.MATCH_WITH_STATUS,BasicMatch.MATCH_TYPE_EQUALS,status);
                 users = rabean.filterByQuery(query,record,size, AccessRulesConstants.VIEW_END_ENTITY);
               }
               oldaction=OLD_ACTION_LISTUSERS;
               oldactionvalue=status;
             }
             else{
               blank=true;
             }
           }
         }else{
           if( request.getParameter(BUTTON_ISREVOKED) != null){
               String serialnumber = request.getParameter(TEXTFIELD_SERIALNUMBER);  
               if(serialnumber != null){
                 serialnumber=serialnumber.trim();
                 if(!serialnumber.equals("")){
                   record=0;   
                   users = rabean.filterByCertificateSerialNumber(serialnumber,record,size);
                   oldaction=OLD_ACTION_ISREVOKED;
                   oldactionvalue=serialnumber;  
                 }
               }
           }else{
             if( request.getParameter(BUTTON_FINDTOKEN) != null){
               String tokenserialnumber = request.getParameter(TEXTFIELD_TOKENSERIALNUMBER);  
               if(tokenserialnumber != null){
                 tokenserialnumber=tokenserialnumber.trim();
                 if(!tokenserialnumber.equals("")){
                   record=0;   
                   users = rabean.filterByTokenSN(tokenserialnumber,record,size);
                   oldaction=OLD_ACTION_FINDTOKEN;
                   oldactionvalue=tokenserialnumber;  
                 }
               }

           }else{
             if( request.getParameter(BUTTON_LISTEXPIRED) != null){
               String days = request.getParameter(TEXTFIELD_DAYS); 
               if(days != null){
                 days=days.trim();
                 if(!days.equals("")){                
                   record=0;   
                   users = rabean.filterByExpiringCertificates(days,record,size);

                   oldaction=OLD_ACTION_LISTEXPIRED;
                   oldactionvalue=days; 
                 }
               }
            }else{
             if( request.getParameter(BUTTON_ADVANCEDLIST) != null){
               oldaction = OLD_ACTION_ADVANCEDLIST;
               oldmatchwithrow1 = request.getParameter(SELECT_MATCHWITH_ROW1);
               oldmatchwithrow2 = request.getParameter(SELECT_MATCHWITH_ROW2);
               oldmatchwithrow3 = request.getParameter(SELECT_MATCHWITH_ROW3);
               oldmatchwithrow4 = request.getParameter(SELECT_MATCHWITH_ROW4);
               oldmatchtyperow1 = request.getParameter(SELECT_MATCHTYPE_ROW1);
               oldmatchtyperow2 = request.getParameter(SELECT_MATCHTYPE_ROW2);
               oldmatchtyperow3 = request.getParameter(SELECT_MATCHTYPE_ROW3);
               oldconnectorrow2 = request.getParameter(SELECT_CONNECTOR_ROW2);
               oldconnectorrow3 = request.getParameter(SELECT_CONNECTOR_ROW3);
               oldconnectorrow4 = request.getParameter(SELECT_CONNECTOR_ROW4);
               olddayrow4 = request.getParameter(SELECT_DAY_ROW4); 
               olddayrow5 = request.getParameter(SELECT_DAY_ROW5); 
               oldmonthrow4 = request.getParameter(SELECT_MONTH_ROW4);
               oldmonthrow5 = request.getParameter(SELECT_MONTH_ROW5);
               oldyearrow4 = request.getParameter(SELECT_YEAR_ROW4);
               oldyearrow5 = request.getParameter(SELECT_YEAR_ROW5);
               oldtimerow4 = request.getParameter(SELECT_TIME_ROW4);
               oldtimerow5 = request.getParameter(SELECT_TIME_ROW5);              

               int matchwithrow1 = (request.getParameter(SELECT_MATCHWITH_ROW1)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHWITH_ROW1)));
               int matchwithrow2 = (request.getParameter(SELECT_MATCHWITH_ROW2)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHWITH_ROW2)));
               int matchwithrow3 = (request.getParameter(SELECT_MATCHWITH_ROW3)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHWITH_ROW3)));
               int matchwithrow4 = (request.getParameter(SELECT_MATCHWITH_ROW4)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHWITH_ROW4)));
               int matchtyperow1 = (request.getParameter(SELECT_MATCHTYPE_ROW1)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHTYPE_ROW1)));
               int matchtyperow2 = (request.getParameter(SELECT_MATCHTYPE_ROW2)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHTYPE_ROW2)));
               int matchtyperow3 = (request.getParameter(SELECT_MATCHTYPE_ROW3)==null?-1:Integer.parseInt(request.getParameter(SELECT_MATCHTYPE_ROW3)));
               int connectorrow2 = (request.getParameter(SELECT_CONNECTOR_ROW2)==null?-1:Integer.parseInt(request.getParameter(SELECT_CONNECTOR_ROW2)));
               int connectorrow3 = (request.getParameter(SELECT_CONNECTOR_ROW3)==null?-1:Integer.parseInt(request.getParameter(SELECT_CONNECTOR_ROW3)));
               int connectorrow4 = (request.getParameter(SELECT_CONNECTOR_ROW4)==null?-1:Integer.parseInt(request.getParameter(SELECT_CONNECTOR_ROW4)));
               int dayrow4       = (request.getParameter(SELECT_DAY_ROW4)==null?-1:Integer.parseInt(request.getParameter(SELECT_DAY_ROW4)));
               int dayrow5       = (request.getParameter(SELECT_DAY_ROW5)==null?-1:Integer.parseInt(request.getParameter(SELECT_DAY_ROW5)));
               int monthrow4     = (request.getParameter(SELECT_MONTH_ROW4)==null?-1:Integer.parseInt(request.getParameter(SELECT_MONTH_ROW4)));
               int monthrow5     = (request.getParameter(SELECT_MONTH_ROW5)==null?-1:Integer.parseInt(request.getParameter(SELECT_MONTH_ROW5)));
               int yearrow4      = (request.getParameter(SELECT_YEAR_ROW4)==null?-1:Integer.parseInt(request.getParameter(SELECT_YEAR_ROW4)));
               int yearrow5      = (request.getParameter(SELECT_YEAR_ROW5)==null?-1:Integer.parseInt(request.getParameter(SELECT_YEAR_ROW5)));
               int timerow4      = (request.getParameter(SELECT_TIME_ROW4)==null?-1:Integer.parseInt(request.getParameter(SELECT_TIME_ROW4)));
               int timerow5      = (request.getParameter(SELECT_TIME_ROW5)==null?-1:Integer.parseInt(request.getParameter(SELECT_TIME_ROW5)));
               
               String matchvaluerow1 = null;
               String matchvaluerow2 = null;
               String matchvaluerow3 = null;
                
               boolean matchadded = false; 

               if(matchwithrow1 == UserMatch.MATCH_WITH_ENDENTITYPROFILE || matchwithrow1 == UserMatch.MATCH_WITH_CERTIFICATEPROFILE){
                    matchvaluerow1 = request.getParameter(SELECT_MATCHVALUE_ROW1);
                    if(matchvaluerow1 == null || matchvaluerow1.equals("0")) matchvaluerow1 = null;
               }else{
                  if(matchwithrow1 == UserMatch.MATCH_WITH_STATUS || matchwithrow1 == UserMatch.MATCH_WITH_CA){
                    matchvaluerow1 = request.getParameter(SELECT_MATCHVALUE_ROW1);
                  }else{
                    matchvaluerow1 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW1);
                  } 
               } 
               if(matchwithrow2 == UserMatch.MATCH_WITH_ENDENTITYPROFILE || matchwithrow2 == UserMatch.MATCH_WITH_CERTIFICATEPROFILE){
                 matchvaluerow2 = request.getParameter(SELECT_MATCHVALUE_ROW2);
                 if(matchvaluerow2 == null || matchvaluerow2.equals("0")) matchvaluerow2 = null;
               }else{
                  if(matchwithrow2 == UserMatch.MATCH_WITH_STATUS || matchwithrow2 == UserMatch.MATCH_WITH_CA){
                    matchvaluerow2 = request.getParameter(SELECT_MATCHVALUE_ROW2);
                  }else{
                     matchvaluerow2 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW2);
                  }                 
               }

               if(matchwithrow3 == UserMatch.MATCH_WITH_ENDENTITYPROFILE || matchwithrow3 == UserMatch.MATCH_WITH_CERTIFICATEPROFILE){
                 matchvaluerow3 = request.getParameter(SELECT_MATCHVALUE_ROW3);
                 if(matchvaluerow3 == null || matchvaluerow3.equals("0")) matchvaluerow3 = null; 
               }else{
                  if(matchwithrow3 == UserMatch.MATCH_WITH_STATUS || matchwithrow3 == UserMatch.MATCH_WITH_CA){
                    matchvaluerow3   = request.getParameter(SELECT_MATCHVALUE_ROW3);
                  }else{
                    matchvaluerow3    = request.getParameter(TEXTFIELD_MATCHVALUE_ROW3);
                  }                 
               } 


               oldmatchvaluerow1=matchvaluerow1;
               oldmatchvaluerow2=matchvaluerow2;
               oldmatchvaluerow3=matchvaluerow3;    

              Query query = new Query(Query.TYPE_USERQUERY);

              if(matchwithrow1 != -1 && matchtyperow1 != -1 && matchvaluerow1 != null){
                 if(!matchvaluerow1.trim().equals("")){
                   query.add(matchwithrow1,matchtyperow1, matchvaluerow1);
                   matchadded = true; 
                 } 
              }
              if(connectorrow2 != -1 && matchwithrow2 != -1 && matchtyperow2 != -1 && matchvaluerow2 != null){
                 if(!matchvaluerow2.trim().equals("")){
                   query.add(connectorrow2);
                   query.add(matchwithrow2,matchtyperow2, matchvaluerow2);
                   matchadded = true; 
                 } 
              }
              if(connectorrow3 != -1 && matchwithrow3 != -1 && matchtyperow3 != -1 && matchvaluerow3 != null){
                 if(!matchvaluerow3.trim().equals("")){
                   query.add(connectorrow3);
                   query.add(matchwithrow3,matchtyperow3, matchvaluerow3);
                   matchadded = true; 
                 } 
              }
              Date startdate = null;
              Date enddate = null;
              Calendar querytime = Calendar.getInstance();
              if( matchwithrow4 != -1 ){
                querytime.set(yearrow4, monthrow4, dayrow4+1, timerow4, 0 ,0); 
                startdate = querytime.getTime();
                querytime.set(yearrow5, monthrow5, dayrow5+1, timerow5, 0 ,0); 
                enddate = querytime.getTime();
              }

              if(connectorrow4 != -1 && matchwithrow4 != -1 ){
            	  if ( matchadded ) {
                      query.add(matchwithrow4, startdate, enddate, connectorrow4);
            	  } else {
                      query.add(matchwithrow4, startdate, enddate);
            	  }
              }

              if(query.isLegalQuery()){
                users = rabean.filterByQuery(query,record,size, AccessRulesConstants.VIEW_END_ENTITY);  
              }else{
                 illegalquery = true;
              }

              
 
            }else{
            users = rabean.getUsers(record,size);
            }}}}}}}
          }
        }
      }
    }
  }
  if(users != null){ 
    numcheckboxes= users.length;
  }

  if(blank)
    rabean.clearUsers();

  
    int[] availablestatuses = {EndEntityConstants.STATUS_NEW, EndEntityConstants.STATUS_FAILED ,EndEntityConstants.STATUS_INITIALIZED, 
                               EndEntityConstants.STATUS_INPROCESS, EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_REVOKED,
                               EndEntityConstants.STATUS_HISTORICAL};
    String[] availablestatustexts = {"STATUSNEW", "STATUSFAILED", "STATUSINITIALIZED", "STATUSINPROCESS", "STATUSGENERATED",
                                     "STATUSREVOKED", "STATUSHISTORICAL"}; 

    if(globalconfiguration.getEnableKeyRecovery()){
      int[] tempintarray = {EndEntityConstants.STATUS_NEW, EndEntityConstants.STATUS_FAILED ,EndEntityConstants.STATUS_INITIALIZED, 
                               EndEntityConstants.STATUS_INPROCESS, EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_REVOKED,
                               EndEntityConstants.STATUS_HISTORICAL, EndEntityConstants.STATUS_KEYRECOVERY}; 
       
      String[] tempstringarray = {"STATUSNEW", "STATUSFAILED", "STATUSINITIALIZED", "STATUSINPROCESS", "STATUSGENERATED",
                                  "STATUSREVOKED", "STATUSHISTORICAL", "STATUSKEYRECOVERY"};
      availablestatuses=tempintarray;
      availablestatustexts=tempstringarray; 
    }

    if(users != null) {
      if(rabean.getResultSize() >= rabean.getMaximumQueryRowCount()) {
        largeresult = true; 
      }
    }

%>

<%@ include file="listendentitieshtml.jspf" %>
