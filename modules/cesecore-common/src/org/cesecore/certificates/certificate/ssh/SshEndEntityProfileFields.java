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
package org.cesecore.certificates.certificate.ssh;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * @version $Id$
 *
 */
public abstract class SshEndEntityProfileFields {

    public static final String SSH_FIELD_ORDER = "SSH_FIELD_ORDER";
    public static final String SSH_PRINCIPAL = "PRINCIPAL";
    public static final int SSH_PRINCIPAL_FIELD_NUMBER = 200;
    public static final String SSH_CRITICAL_OPTION_FORCE_COMMAND = "SSH_CRITICAL_OPTION_FORCE_COMMAND";
    public static final int SSH_CRITICAL_OPTION_FORCE_COMMAND_FIELD_NUMBER = 201;
    public static final String SSH_CRITICAL_OPTION_SOURCE_ADDRESS = "SSH_CRITICAL_OPTION_SOURCE_ADDRESS";
    public static final int SSH_CRITICAL_OPTION_SOURCE_ADDRESS_FIELD_NUMBER = 202;

    private static final Map<String, String> sshFields = new TreeMap<>();
    private static final Map<Integer, String> sshFieldsLanguageKeys = new HashMap<>();

    static {
        sshFields.put(SSH_PRINCIPAL, "Principal");
        sshFieldsLanguageKeys.put(SSH_PRINCIPAL_FIELD_NUMBER, "SSH_PRINCIPAL");
    }

    public static boolean isSshField(final String field) {
        return sshFields.containsKey(field);
    }

    public static Map<String, String> getSshFields() {
        return sshFields;
    }
    
    public static String getLanguageKey(int fieldNumber) {
        return sshFieldsLanguageKeys.get(fieldNumber);
    }

}
