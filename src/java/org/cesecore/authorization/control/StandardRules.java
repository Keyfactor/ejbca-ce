/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.authorization.control;

/**
 * @version $Id$
 */

public enum StandardRules {
	AUDITLOGMANAGE ("/secureaudit/management/manage"),
	AUDITLOGEXPORT("/secureaudit/auditor/export"),
	AUDITLOGSELECT("/secureaudit/auditor/select"),
	AUDITLOGVERIFY("/secureaudit/auditor/verify"),
	CAACCESSBASE("/ca"),
	CAACCESS("/ca/"),
	CAACCESSANYCA("/ca/-1"),
	CAFUNCTIONALITY("/ca_functionality"),
	CAREMOVE(CAFUNCTIONALITY.resource()+"/remove_ca"),
	CAADD(CAFUNCTIONALITY.resource()+"/add_ca"),
	CAEDIT(CAFUNCTIONALITY.resource()+"/edit_ca"),
	CREATECERT(CAFUNCTIONALITY.resource()+"/create_certificate"),
	EDITCERTIFICATEPROFILE(CAFUNCTIONALITY.resource()+"/edit_certificate_profiles"),
	CREATECRL(CAFUNCTIONALITY.resource()+"/create_crl"),
	SYSTEMFUNCTIONALITY("/system_functionality"),
	EDITROLES(SYSTEMFUNCTIONALITY.resource()+"/edit_administrator_privileges"),
	RECOVERY("/recovery"),
	BACKUP(RECOVERY.resource()+"/backup"),
	RESTORE(RECOVERY.resource()+"/restore");
	
	// TODO: search _ACCESS_RULE
	private final String resource;
	
	StandardRules(String resource) {
        this.resource = resource;
    }

	public String resource() {
		return this.resource;
	}
	
	public String toString() {
		return this.resource;
	}

}
