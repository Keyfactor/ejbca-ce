<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.rainterface.SortBy,org.ejbca.ui.web.admin.loginterface.LogEntryView,
                 org.ejbca.ui.web.admin.loginterface.LogInterfaceBean, org.ejbca.core.model.log.LogEntry, org.ejbca.core.model.log.Admin, org.ejbca.core.model.ra.raadmin.AdminPreference,
                 javax.ejb.CreateException, org.ejbca.util.query.*, java.util.Calendar, java.util.Date, java.text.DateFormat, java.util.Locale,
                 java.util.HashMap, java.util.Map, java.util.Collection, java.util.Iterator, java.util.TreeMap, org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper, org.ejbca.core.model.log.LogConstants, org.ejbca.core.model.log.ILogExporter, 
                 org.ejbca.core.model.log.CsvLogExporter, org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="logbean" scope="session" class="org.ejbca.ui.web.admin.loginterface.LogInterfaceBean" />


<%! // Declarations

  static final String ACTION                             = "action";
  static final String ACTION_LISTLOG                     = "listlog";
  static final String ACTION_CHANGEFILTERMODETO_BASIC    = "changefiltermodetobasic";
  static final String ACTION_CHANGEFILTERMODETO_ADVANCED = "changefiltermodetoadvanced";
  static final String ACTION_CHANGEENTRIESPERPAGE        = "changeentriesperpage";


  static final String OLD_ACTION               = "oldaction";
  static final String OLD_ACTION_VIEWLAST      = "oldactionviewlast";
  static final String OLD_ACTION_ADVANCEDLIST  = "oldactionadvancedlist";
  static final String OLD_ACTION_NOACTION      = "oldactionnoaction";  
  static final String OLD_ACTION_VALUE         = "oldactionvalue";

  static final String OLD_VIEWLASTENTRIES      = "oldviewlastentries";

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


  static final String BUTTON_VIEWLAST          = "buttonviewlast"; 
  static final String BUTTON_RELOAD            = "buttonreload";
  static final String BUTTON_EXPORTCSV         = "buttonexportcsv";
  static final String BUTTON_ADVANCEDLIST      = "buttonadvancedlist";

  static final String BUTTON_NEXT              = "buttonnext";
  static final String BUTTON_PREVIOUS          = "buttonprevious";

  static final String SELECT_SIGNCSVCA         = "selectsigncsvca";
  static final String SELECT_EMPTYVALUE        = "--";

  static final String SORTBY_TIME_ACC         = "sortbytimeaccending";
  static final String SORTBY_TIME_DEC         = "sortbytimedecending";
  static final String SORTBY_ADMINDATA_ACC    = "sortbyadmindataaccending";
  static final String SORTBY_ADMINDATA_DEC    = "sortbyadmindatadecending";
  static final String SORTBY_ADMINTYPE_ACC    = "sortbyadmintypeaccending";
  static final String SORTBY_ADMINTYPE_DEC    = "sortbyadmintypedecending";
  static final String SORTBY_CA_ACC           = "sortbycaaccending";
  static final String SORTBY_CA_DEC           = "sortbycadecending";
  static final String SORTBY_MODULE_ACC       = "sortbymoduleaccending";
  static final String SORTBY_MODULE_DEC       = "sortbymoduledecending";
  static final String SORTBY_USERNAME_ACC     = "sortbyusernameaccending";
  static final String SORTBY_USERNAME_DEC     = "sortbyusernamedecending";
  static final String SORTBY_CERTIFICATE_ACC  = "sortbycertificateaccending";
  static final String SORTBY_CERTIFICATE_DEC  = "sortbycertificatedecending";
  static final String SORTBY_EVENT_ACC        = "sortbyeventaccending";
  static final String SORTBY_EVENT_DEC        = "sortbyeventdecending";
  static final String SORTBY_COMMENT_ACC      = "sortbycommentaccending";
  static final String SORTBY_COMMENT_DEC      = "sortbycommentdecending";

  static final String SELECT_VIEWLOGDEVICE      = "selectviewlogdevice";
  static final String SELECT_VIEWLASTENTRIES    = "selectviewlastentries";
  static final String SELECT_ENTRIESPERPAGE     = "selectentriesperpage";
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

  static final String TEXTFIELD_MATCHVALUE_ROW1 = "textfieldmatchvaluerow1";
  static final String TEXTFIELD_MATCHVALUE_ROW2 = "textfieldmatchvaluerow2";
  static final String TEXTFIELD_MATCHVALUE_ROW3 = "textfieldmatchvaluerow3";

  static final String HIDDEN_SORTBY             = "hiddensortby";
  static final String HIDDEN_RECORDNUMBER       = "hiddenrecordnumber"; 
  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_CERTSERNO          = "hiddencertserno";
  static final String HIDDEN_ADMINSERNO         = "hiddenadminserno";
  static final String HIDDEN_TIMESTAMP          = "hiddentimestamp";

  static final String VALUE_NONE                = "-1";
  static final String ALL_STATUS                = "-1";

  static final String USER_PARAMETER            = "username";
  static final String TIMESTAMP_PARAMETER       = ViewEndEntityHelper.TIMESTAMP_PARAMETER;
  static final String CERTSERNO_PARAMETER       = "certsernoparameter";

  static final String[] VIEWLASTTIMESTEXTS      = {"15MIN", "1HOUR", "6HOURS", "1DAY", "7DAYS"};
  static final int[]    VIEWLASTTIMES           = {15, 60, 360, 1440, 10080};
%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "log_functionality/view_log");  
                                            logbean.initialize(request,ejbcawebbean);
                                            

  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";  
  final String VIEWUSER_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath() + "/viewendentity.jsp";

  final String[] ADMINTYPES             = Admin.ADMINTYPETEXTS;

  RequestHelper.setDefaultCharacterEncoding(request);

  String oldaction        = OLD_ACTION_NOACTION; 
  String oldactionvalue   = request.getParameter(OLD_ACTION_VALUE);
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

  String sortby         = SORTBY_TIME_DEC;

  String THIS_FILENAME            =  globalconfiguration.getLogPath()  + "/viewlog.jsp";
  LogEntryView[] logentries             = null;

  boolean illegalquery            = false;
  boolean largeresult             = false;
  boolean cmsnotactive             = false;


  int filtermode = ejbcawebbean.getLastLogFilterMode();


  // Determine action 
  int record   = 0;
  int size = ejbcawebbean.getLogEntriesPerPage();
 
  if (request.getParameter(HIDDEN_RECORDNUMBER) != null ){
    record =  Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER)); 
  } 

  if (request.getParameter(HIDDEN_SORTBY) != null ){
    sortby =  request.getParameter(HIDDEN_SORTBY); 
  } 

  if( request.getParameter(OLD_ACTION) != null){
    oldaction = request.getParameter(OLD_ACTION);
    if(request.getParameter(OLD_ACTION_VALUE) != null){
      oldactionvalue= request.getParameter(OLD_ACTION_VALUE);
    }
  }

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_CHANGEFILTERMODETO_ADVANCED)){
      ejbcawebbean.setLastLogFilterMode(AdminPreference.FILTERMODE_ADVANCED);
      filtermode = AdminPreference.FILTERMODE_ADVANCED;
    }
    if( request.getParameter(ACTION).equals(ACTION_CHANGEFILTERMODETO_BASIC)){
      ejbcawebbean.setLastLogFilterMode(AdminPreference.FILTERMODE_BASIC);
      filtermode = AdminPreference.FILTERMODE_BASIC;    
    }

    if( request.getParameter(ACTION).equals(ACTION_CHANGEENTRIESPERPAGE)){
      size = Integer.parseInt(request.getParameter(SELECT_ENTRIESPERPAGE));
      ejbcawebbean.setLogEntriesPerPage(size);
    }
 
   if( request.getParameter(BUTTON_PREVIOUS) != null ){
     record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
     record -= ejbcawebbean.getLogEntriesPerPage();
     if(record < 0 ) record=0;
   }
   if( request.getParameter(BUTTON_NEXT) != null ){
     record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
     record += ejbcawebbean.getLogEntriesPerPage();
   }

   cmsnotactive = false;
   if ( request.getParameter(BUTTON_EXPORTCSV)!=null ){
       String signcsvca = request.getParameter(SELECT_SIGNCSVCA);
       if ( (signcsvca != null) && ((signcsvca.equals(SELECT_EMPTYVALUE)) || (signcsvca.length() == 0)) ) {
    	   signcsvca = null;
       }
	   CsvLogExporter exporter = new CsvLogExporter();
	   exporter.setSigningCA(signcsvca);
	   try {
		   byte[] export = logbean.exportLastQuery(request.getParameter(SELECT_VIEWLOGDEVICE), exporter);
		   if (export != null) {
			   String name = "logexport.csv";
			   String ct = "text/csv";
			   if (signcsvca != null) {
				   name = "logexport.p7m";
				   ct = "application/octet-stream";
			   }
			   RequestHelper.sendBinaryBytes(export, response, ct, name);
			   // This is a workaround to avoid error "getOutputStream() has already been called for this response"
			   out.clear();
			   out = pageContext.pushBody();
			   return;		   
		   }		   
	   } catch (Exception e) {
		   if (e instanceof ExtendedCAServiceNotActiveException) {
			   cmsnotactive = true;
		   } else if (e instanceof IllegalQueryException) {
			   illegalquery = true;
		   } else {
			   throw e;
		   }
	   }
   }


   if(  request.getParameter(BUTTON_RELOAD)!=null &&  oldaction.equals(OLD_ACTION_VIEWLAST) ){
       logentries = logbean.filterByTime(request.getParameter(SELECT_VIEWLOGDEVICE), VIEWLASTTIMES[Integer.parseInt(oldactionvalue)],record,size);
     }else{
       if( request.getParameter(BUTTON_RELOAD)!=null && oldaction.equals(OLD_ACTION_ADVANCEDLIST) ){

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
    
              Query query = new Query(Query.TYPE_LOGQUERY);

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
                querytime.set(yearrow4, monthrow4, dayrow4, timerow4, 0 ,0); 
                startdate = querytime.getTime();
                querytime.set(yearrow5, monthrow5, dayrow5, timerow5, 0 ,0); 
                enddate = querytime.getTime();
              }

              if(connectorrow4 != -1 && matchwithrow4 != -1 ){
                   query.add(connectorrow4);
                   query.add(startdate, enddate);
              }

              if(connectorrow4 == -1 && !matchadded && matchwithrow4 != -1 ){
                   query.add(startdate, enddate);
              }


              if(query.isLegalQuery()){
                logentries  = logbean.filterByQuery(request.getParameter(SELECT_VIEWLOGDEVICE), query,record,size);  
              }else{
                 illegalquery = true;
              } 

     }
     else{
       if( request.getParameter(BUTTON_VIEWLAST) != null){
         String timeindex = request.getParameter(SELECT_VIEWLASTENTRIES); 
         if(!timeindex.equals("")){
           record=0;
           logentries  = logbean.filterByTime(request.getParameter(SELECT_VIEWLOGDEVICE), VIEWLASTTIMES[Integer.parseInt(timeindex)],record,size);
           oldaction=OLD_ACTION_VIEWLAST;
           oldactionvalue=timeindex;
         }else{
           oldaction=OLD_ACTION_VIEWLAST;
           oldactionvalue="-1";         
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

             if(matchwithrow1 == LogMatch.MATCH_WITH_SPECIALADMIN || matchwithrow1 == LogMatch.MATCH_WITH_EVENT || 
                matchwithrow1 == LogMatch.MATCH_WITH_MODULE || matchwithrow1 == LogMatch.MATCH_WITH_CA){
                  matchvaluerow1 = request.getParameter(SELECT_MATCHVALUE_ROW1);
             }else{
               if(matchwithrow1 == LogMatch.MATCH_WITH_ADMINCERTIFICATE)
                  matchvaluerow1 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW1).toUpperCase();
               else
                 if(matchwithrow1 == LogMatch.MATCH_WITH_CERTIFICATE)
                   matchvaluerow1 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW1).toUpperCase();
                 else{ 
                  matchvaluerow1 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW1);  
                }
              } 
              if(matchwithrow2 == LogMatch.MATCH_WITH_SPECIALADMIN || matchwithrow2 == LogMatch.MATCH_WITH_EVENT || 
                matchwithrow2 == LogMatch.MATCH_WITH_MODULE || matchwithrow2 == LogMatch.MATCH_WITH_CA){
                    matchvaluerow2 = request.getParameter(SELECT_MATCHVALUE_ROW2);
              }else{
                  if(matchwithrow2 == LogMatch.MATCH_WITH_ADMINCERTIFICATE)
                    matchvaluerow2 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW2).toUpperCase();
                  else
                    if(matchwithrow2 == LogMatch.MATCH_WITH_CERTIFICATE)
                      matchvaluerow2 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW2).toUpperCase();
                    else{
                      matchvaluerow2 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW2);              
                    }
               }
               if(matchwithrow3 == LogMatch.MATCH_WITH_SPECIALADMIN || matchwithrow3 == LogMatch.MATCH_WITH_EVENT || 
                 matchwithrow3 == LogMatch.MATCH_WITH_MODULE || matchwithrow3 == LogMatch.MATCH_WITH_CA){
                  matchvaluerow3 = request.getParameter(SELECT_MATCHVALUE_ROW3);
               }else{
                    if(matchwithrow3 == LogMatch.MATCH_WITH_ADMINCERTIFICATE)
                      matchvaluerow3 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW3).toUpperCase();
                    else
                      if(matchwithrow3 == LogMatch.MATCH_WITH_CERTIFICATE)
                        matchvaluerow3 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW3).toUpperCase();
                      else{
                       matchvaluerow3 = request.getParameter(TEXTFIELD_MATCHVALUE_ROW3);
                      }   
               }
                         

               oldmatchvaluerow1=matchvaluerow1;
               oldmatchvaluerow2=matchvaluerow2;
               oldmatchvaluerow3=matchvaluerow3;    

              Query query = new Query(Query.TYPE_LOGQUERY);

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
                querytime.set(yearrow4, monthrow4, dayrow4, timerow4, 0 ,0); 
                startdate = querytime.getTime();
                querytime.set(yearrow5, monthrow5, dayrow5, timerow5, 0 ,0); 
                enddate = querytime.getTime();
              }


              if(connectorrow4 != -1 && matchwithrow4 != -1 ){
                   query.add(connectorrow4);
                   query.add(startdate, enddate);
              }

              if(connectorrow4 == -1 && !matchadded && matchwithrow4 != -1 ){
                   query.add(startdate, enddate);
              }

              if(query.isLegalQuery()){
                logentries  = logbean.filterByQuery(request.getParameter(SELECT_VIEWLOGDEVICE), query,record,size);  
              }else{
                 illegalquery = true;
              }

              
 
            }else{
            logentries  = logbean.getEntries (record,size);
            }
          }
        }
      }
   }


   if( request.getParameter(SORTBY_TIME_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_TIME_ACC;
     logbean.sortUserData(SortBy.TIME,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_TIME_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_TIME_DEC;
     logbean.sortUserData(SortBy.TIME,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_ADMINTYPE_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ADMINTYPE_ACC;
     logbean.sortUserData(SortBy.ADMINTYPE,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_ADMINTYPE_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ADMINTYPE_DEC;
     logbean.sortUserData(SortBy.ADMINTYPE,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_ADMINDATA_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ADMINDATA_ACC;
     logbean.sortUserData(SortBy.ADMINDATA,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_ADMINDATA_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ADMINDATA_DEC;
     logbean.sortUserData(SortBy.ADMINDATA,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_CA_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_CA_ACC;
     logbean.sortUserData(SortBy.CA,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_CA_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_CA_DEC;
     logbean.sortUserData(SortBy.CA,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_MODULE_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_MODULE_ACC;
     logbean.sortUserData(SortBy.MODULE,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_MODULE_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_MODULE_DEC;
     logbean.sortUserData(SortBy.MODULE,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_USERNAME_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_USERNAME_ACC;
     logbean.sortUserData(SortBy.USERNAME,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_USERNAME_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_USERNAME_DEC;
     logbean.sortUserData(SortBy.USERNAME,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_CERTIFICATE_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_CERTIFICATE_ACC;
     logbean.sortUserData(SortBy.CERTIFICATE,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_CERTIFICATE_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_CERTIFICATE_DEC;
     logbean.sortUserData(SortBy.CERTIFICATE,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_EVENT_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_EVENT_ACC;
     logbean.sortUserData(SortBy.EVENT,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_EVENT_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_EVENT_DEC;
     logbean.sortUserData(SortBy.EVENT,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_COMMENT_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_COMMENT_ACC;
     logbean.sortUserData(SortBy.COMMENT,SortBy.ACCENDING);
     logentries  = logbean.getEntries (record,size);
   }
   if( request.getParameter(SORTBY_COMMENT_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_COMMENT_DEC;
     logbean.sortUserData(SortBy.COMMENT,SortBy.DECENDING);
     logentries  = logbean.getEntries (record,size);
   }

   if(logentries  != null)
     if(logbean.getResultSize() >= LogInterfaceBean.MAXIMUM_QUERY_ROWCOUNT) 
        largeresult = true; 

%>

<%@ include file="viewloghtml.jspf" %>

</html>
