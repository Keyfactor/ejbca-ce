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
    ROLE_ROOT("/"),
	CAACCESSBASE("/ca"),
	CAACCESS("/ca/"),
	CAACCESSANYCA("/ca/-1"),
	CAFUNCTIONALITY("/ca_functionality"),
	CAREMOVE(CAFUNCTIONALITY.resource()+"/remove_ca"),
	CAADD(CAFUNCTIONALITY.resource()+"/add_ca"),
	CAEDIT(CAFUNCTIONALITY.resource()+"/edit_ca"),
	CARENEW(CAFUNCTIONALITY.resource()+"/renew_ca"),
    CAVIEW(CAFUNCTIONALITY.resource()+"/view_ca"),  
	CREATECERT(CAFUNCTIONALITY.resource()+"/create_certificate"),
	CERTIFICATEPROFILEEDIT(CAFUNCTIONALITY.resource()+"/edit_certificate_profiles"),
	CERTIFICATEPROFILEVIEW(CAFUNCTIONALITY.resource()+"/view_certificate_profiles"),
	CREATECRL(CAFUNCTIONALITY.resource()+"/create_crl"),
	SYSTEMFUNCTIONALITY("/system_functionality"),
	EDITROLES(SYSTEMFUNCTIONALITY.resource()+"/edit_administrator_privileges"),
	RECOVERY("/recovery"),
	BACKUP(RECOVERY.resource()+"/backup"),
	RESTORE(RECOVERY.resource()+"/restore"),
    REGULAR_EDITSYSTEMCONFIGURATION(SYSTEMFUNCTIONALITY.resource()+"/edit_systemconfiguration"),
    REGULAR_EDITAVAILABLEEKU(SYSTEMFUNCTIONALITY.resource()+"/edit_available_extended_key_usages"),
    REGULAR_EDITAVAILABLECUSTOMCERTEXTENSION(SYSTEMFUNCTIONALITY.resource()+"/edit_available_custom_certificate_extensions");

	
	private final String resource;
	
	private StandardRules(String resource) {
        this.resource = resource;
    }

	public String resource() {
		return this.resource;
	}

	public String toString() {
		return this.resource;
	}

}
