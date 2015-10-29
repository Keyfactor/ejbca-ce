/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.log;


/**
 * @version $Id$
 */
public interface LogConstants {

    // Public constants

    /*Possible log events, all information events should have an id below 1000 and all error events should have a id above 1000 */
    // Information events. Important all id:s should map to the array EVENTNAMES_INFO.
    public static final int EVENT_INFO_UNKNOWN = 0;
    public static final int EVENT_INFO_ADDEDENDENTITY = 1;
    public static final int EVENT_INFO_CHANGEDENDENTITY = 2;
    public static final int EVENT_INFO_REVOKEDENDENTITY = 3;
    public static final int EVENT_INFO_REVOKEDCERT = 4;
    public static final int EVENT_INFO_DELETEDENDENTITY = 5;
    public static final int EVENT_INFO_EDITSYSTEMCONFIGURATION = 6;
    public static final int EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES = 7;
    public static final int EVENT_INFO_EDITLOGCONFIGURATION = 8;
    public static final int EVENT_INFO_ADMINISTRATORPREFERENCECHANGED = 9;
    public static final int EVENT_INFO_ENDENTITYPROFILE = 10;
    public static final int EVENT_INFO_USERAUTHENTICATION = 11;
    public static final int EVENT_INFO_STORECERTIFICATE = 12;
    public static final int EVENT_INFO_STORECRL = 13;
    public static final int EVENT_INFO_GETLASTCRL = 14;
    public static final int EVENT_INFO_CERTPROFILE = 15;
    public static final int EVENT_INFO_DATABASE = 16;
    public static final int EVENT_INFO_CREATECERTIFICATE = 17;
    public static final int EVENT_INFO_CREATECRL = 18;
    public static final int EVENT_INFO_ADMINISTRATORLOGGEDIN = 19;
    public static final int EVENT_INFO_AUTHORIZEDTORESOURCE = 20;
    public static final int EVENT_INFO_PUBLICWEBUSERCONNECTED = 21;
    public static final int EVENT_INFO_HARDTOKEN_USERDATASENT = 22;
    public static final int EVENT_INFO_HARDTOKENGENERATED = 23;
    public static final int EVENT_INFO_HARDTOKENDATA = 24;
    public static final int EVENT_INFO_HARDTOKENISSUERDATA = 25;
    public static final int EVENT_INFO_HARDTOKENCERTIFICATEMAP = 26;
    public static final int EVENT_INFO_KEYRECOVERY = 27;
    public static final int EVENT_INFO_NOTIFICATION = 28;
    public static final int EVENT_INFO_HARDTOKENVIEWED = 29;
    public static final int EVENT_INFO_CACREATED = 30;
    public static final int EVENT_INFO_CAEDITED = 31;
    public static final int EVENT_INFO_CAREVOKED = 32;
    public static final int EVENT_INFO_HARDTOKENPROFILEDATA = 33;
    public static final int EVENT_INFO_PUBLISHERDATA = 34;
    public static final int EVENT_INFO_USERDATASOURCEDATA = 35;
    public static final int EVENT_INFO_USERDATAFETCHED = 36;
    public static final int EVENT_INFO_UNREVOKEDCERT = 37;
    public static final int EVENT_INFO_APPROVALREQUESTED = 38;
    public static final int EVENT_INFO_APPROVALAPPROVED = 39;
    public static final int EVENT_INFO_APPROVALREJECTED = 40;
    public static final int EVENT_INFO_SERVICESEDITED = 41;
    public static final int EVENT_INFO_SERVICEEXECUTED = 42;
    public static final int EVENT_INFO_REQUESTCERTIFICATE = 43;
    public static final int EVENT_INFO_CARENEWED = 44;
    public static final int EVENT_INFO_CAEXPORTED = 45;
    public static final int EVENT_INFO_USERDATAREMOVED = 46;
    public static final int EVENT_INFO_CUSTOMLOG = 47;
    public static final int EVENT_INFO_PUKVIEWED = 48;
    public static final int EVENT_INFO_STARTING = 49;
    public static final int EVENT_INFO_SIGNEDREQUEST = 50;
    public static final int EVENT_INFO_CAACTIVATIONCODE= 51;

    // Error events. Important all id:s should map to the array EVENTNAMES_ERROR - EVENT_ERROR_BOUNDRARY.
    public static final int EVENT_ERROR_UNKNOWN = 1000;
    public static final int EVENT_ERROR_ADDEDENDENTITY = 1001;
    public static final int EVENT_ERROR_CHANGEDENDENTITY = 1002;
    public static final int EVENT_ERROR_REVOKEDENDENTITY = 1003;
    public static final int EVENT_ERROR_REVOKEDCERT = 1004;
    public static final int EVENT_ERROR_DELETEENDENTITY = 1005;
    public static final int EVENT_ERROR_EDITSYSTEMCONFIGURATION = 1006;
    public static final int EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES = 1007;
    public static final int EVENT_ERROR_EDITLOGCONFIGURATION = 1008;
    public static final int EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED = 1009;
    public static final int EVENT_ERROR_ENDENTITYPROFILE = 1010;
    public static final int EVENT_ERROR_USERAUTHENTICATION = 1011;
    public static final int EVENT_ERROR_STORECERTIFICATE = 1012;
    public static final int EVENT_ERROR_STORECRL = 1013;
    public static final int EVENT_ERROR_GETLASTCRL = 1014;
    public static final int EVENT_ERROR_CERTPROFILE = 1015;
    public static final int EVENT_ERROR_DATABASE = 1016;
    public static final int EVENT_ERROR_CREATECERTIFICATE = 1017;
    public static final int EVENT_ERROR_CREATECRL = 1018;
    public static final int EVENT_ERROR_ADMINISTRATORLOGGEDIN = 1019;
    public static final int EVENT_ERROR_NOTAUTHORIZEDTORESOURCE = 1020;
    public static final int EVENT_ERROR_PUBLICWEBUSERCONNECTED = 1021;
    public static final int EVENT_ERROR_HARDTOKEN_USERDATASENT = 1022;
    public static final int EVENT_ERROR_HARDTOKENGENERATED = 1023;
    public static final int EVENT_ERROR_HARDTOKENDATA = 1024;
    public static final int EVENT_ERROR_HARDTOKENISSUERDATA = 1025;
    public static final int EVENT_ERROR_HARDTOKENCERTIFICATEMAP = 1026;
    public static final int EVENT_ERROR_KEYRECOVERY = 1027;
    public static final int EVENT_ERROR_NOTIFICATION = 1028;
    public static final int EVENT_ERROR_HARDTOKENVIEWED = 1029;
    public static final int EVENT_ERROR_CACREATED = 1030;
    public static final int EVENT_ERROR_CAEDITED = 1031;
    public static final int EVENT_ERROR_CAREVOKED = 1032;
    public static final int EVENT_ERROR_HARDTOKENPROFILEDATA = 1033;
    public static final int EVENT_ERROR_PUBLISHERDATA = 1034;
    public static final int EVENT_ERROR_USERDATASOURCEDATA = 1035;
    public static final int EVENT_ERROR_USERDATAFETCHED = 1036;
    public static final int EVENT_ERROR_UNREVOKEDCERT = 1037;
    public static final int EVENT_ERROR_APPROVALREQUESTED = 1038;
    public static final int EVENT_ERROR_APPROVALAPPROVED = 1039;
    public static final int EVENT_ERROR_APPROVALREJECTED = 1040;
    public static final int EVENT_ERROR_SERVICESEDITED = 1041;
    public static final int EVENT_ERROR_SERVICEEXECUTED = 1042;
    public static final int EVENT_ERROR_REQUESTCERTIFICATE = 1043;
    public static final int EVENT_ERROR_CARENEWED = 1044;
    public static final int EVENT_ERROR_CAEXPORTED = 1045;
    public static final int EVENT_ERROR_USERDATAREMOVED = 1046;
    public static final int EVENT_ERROR_CUSTOMLOG = 1047;
    public static final int EVENT_ERROR_PUKVIEWED = 1048;
    public static final int EVENT_ERROR_STARTING = 1049;
    public static final int EVENT_ERROR_SIGNEDREQUEST = 1050;
    public static final int EVENT_ERROR_CAACTIVATIONCODE = 1051;

    // System event. Used for internal processing.
	public static final int EVENT_SYSTEM_INITILIZED_LOGGING		= 2000;
	public static final int EVENT_SYSTEM_STOPPED_LOGGING			= 2001;
    
    // Indicates the module using the logsession bean.
    public static final int MODULE_CA = 0;
    public static final int MODULE_RA = 1;
    public static final int MODULE_LOG = 2;
    public static final int MODULE_PUBLICWEB = 3;
    public static final int MODULE_ADMINWEB = 4;
    public static final int MODULE_HARDTOKEN = 5;
    public static final int MODULE_KEYRECOVERY = 6;
    public static final int MODULE_AUTHORIZATION = 7;
    public static final int MODULE_APPROVAL = 8;
    public static final int MODULE_SERVICES = 9;
    public static final int MODULE_CUSTOM = 10;

    public static final int EVENT_ERROR_BOUNDRARY = 1000;
    public static final int EVENT_SYSTEM_BOUNDRARY = 2000;

    // Id -> String maps
    public static final String[] EVENTNAMES_INFO = {"EVENT_INFO_UNKNOWN", "EVENT_INFO_ADDEDENDENTITY", "EVENT_INFO_CHANGEDENDENTITY", "EVENT_INFO_REVOKEDENDENTITY", "EVENT_INFO_REVOKEDCERT",
                                                    "EVENT_INFO_DELETEDENDENTITY", "EVENT_INFO_EDITSYSTEMCONFIGURATION", "EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES",
                                                    "EVENT_INFO_EDITLOGCONFIGURATION", "EVENT_INFO_ADMINISTRATORPREFERENCECHANGED", "EVENT_INFO_ENDENTITYPROFILE", "EVENT_INFO_USERAUTHENTICATION",
                                                    "EVENT_INFO_STORECERTIFICATE", "EVENT_INFO_STORECRL", "EVENT_INFO_GETLASTCRL", "EVENT_INFO_CERTPROFILE", "EVENT_INFO_DATABASE",
                                                    "EVENT_INFO_CREATECERTIFICATE", "EVENT_INFO_CREATECRL", "EVENT_INFO_ADMINISTRATORLOGGEDIN", "EVENT_INFO_AUTHORIZEDTORESOURCE",
                                                    "EVENT_INFO_PUBLICWEBUSERCONNECTED", "EVENT_INFO_HARDTOKEN_USERDATASENT", "EVENT_INFO_HARDTOKENGENERATED", "EVENT_INFO_HARDTOKENDATA",
                                                    "EVENT_INFO_HARDTOKENISSUERDATA", "EVENT_INFO_HARDTOKENCERTIFICATEMAP", "EVENT_INFO_KEYRECOVERY", "EVENT_INFO_NOTIFICATION",
                                                    "EVENT_INFO_HARDTOKENVIEWED", "EVENT_INFO_CACREATED", "EVENT_INFO_CAEDITED", "EVENT_INFO_CAREVOKED", "EVENT_INFO_HARDTOKENPROFILEDATA", 
                                                    "EVENT_INFO_PUBLISHERDATA", "EVENT_INFO_USERDATASOURCEDATA", "EVENT_INFO_USERDATAFETCHED", "EVENT_INFO_UNREVOKEDCERT",
                                                    "EVENT_INFO_APPROVALREQUESTED","EVENT_INFO_APPROVALAPPROVED","EVENT_INFO_APPROVALREJECTED","EVENT_INFO_SERVICESEDITED","EVENT_INFO_SERVICEEXECUTED",
                                                    "EVENT_INFO_REQUESTCERTIFICATE", "EVENT_INFO_CARENEWED", "EVENT_INFO_CAEXPORTED", "EVENT_INFO_USERDATAREMOVED", "EVENT_INFO_CUSTOMLOG",
                                                    "EVENT_INFO_PUKVIEWED", "EVENT_INFO_STARTING", "EVENT_INFO_SIGNEDREQUEST", "EVENT_INFO_CAACTIVATIONCODE"};


    public static final String[] EVENTNAMES_ERROR = {"EVENT_ERROR_UNKNOWN", "EVENT_ERROR_ADDEDENDENTITY", "EVENT_ERROR_CHANGEDENDENTITY", "EVENT_ERROR_REVOKEDENDENTITY", "EVENT_ERROR_REVOKEDCERT",
                                                     "EVENT_ERROR_DELETEENDENTITY", "EVENT_ERROR_EDITSYSTEMCONFIGURATION", "EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES",
                                                     "EVENT_ERROR_EDITLOGCONFIGURATION", "EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED", "EVENT_ERROR_ENDENTITYPROFILE", "EVENT_ERROR_USERAUTHENTICATION",
                                                     "EVENT_ERROR_STORECERTIFICATE", "EVENT_ERROR_STORECRL", "EVENT_ERROR_GETLASTCRL", "EVENT_ERROR_CERTPROFILE", "EVENT_ERROR_DATABASE",
                                                     "EVENT_ERROR_CREATECERTIFICATE", "EVENT_ERROR_CREATECRL", "EVENT_ERROR_ADMINISTRATORLOGGEDIN", "EVENT_ERROR_NOTAUTHORIZEDTORESOURCE",
                                                     "EVENT_ERROR_PUBLICWEBUSERCONNECTED", "EVENT_ERROR_HARDTOKEN_USERDATASENT", "EVENT_ERROR_HARDTOKENGENERATED", "EVENT_ERROR_HARDTOKENDATA",
                                                     "EVENT_ERROR_HARDTOKENISSUERDATA", "EVENT_ERROR_HARDTOKENCERTIFICATEMAP", "EVENT_ERROR_KEYRECOVERY", "EVENT_ERROR_NOTIFICATION",
                                                     "EVENT_ERROR_HARDTOKENVIEWED", "EVENT_ERROR_CACREATED", "EVENT_ERROR_CAEDITED", "EVENT_ERROR_CAREVOKED", "EVENT_ERROR_HARDTOKENPROFILEDATA",
                                                     "EVENT_ERROR_PUBLISHERDATA", "EVENT_ERROR_USERDATASOURCEDATA", "EVENT_ERROR_USERDATAFETCHED", "EVENT_ERROR_UNREVOKEDCERT",
                                                     "EVENT_ERROR_APPROVALREQUESTED","EVENT_ERROR_APPROVALAPPROVED","EVENT_ERROR_APPROVALREJECTED","EVENT_ERROR_SERVICESEDITED",
                                                     "EVENT_ERROR_SERVICEEXECUTED", "EVENT_ERROR_REQUESTCERTIFICATE", "EVENT_ERROR_CARENEWED", "EVENT_ERROR_CAEXPORTED", "EVENT_ERROR_USERDATAREMOVED", 
                                                     "EVENT_ERROR_CUSTOMLOG","EVENT_ERROR_PUKVIEWED", "EVENT_ERROR_STARTING", "EVENT_ERROR_SIGNEDREQUEST", "EVENT_ERROR_CAACTIVATIONCODE"};
    
    public static final String[] EVENTNAMES_SYSTEM = {"EVENT_SYSTEM_INITILIZED_LOGGING", "EVENT_SYSTEM_STOPPED_LOGGING"};

    public static final String[] MODULETEXTS = {"CA", "RA", "LOG", "PUBLICWEB", "ADMINWEB", "HARDTOKEN", "KEYRECOVERY", "AUTHORIZATION","APPROVAL","SERVICE","CUSTOM"};

    public static final String NO_AUTHENTICATION_TOKEN = "none";
}
