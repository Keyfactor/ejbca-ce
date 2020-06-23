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

/**
 * Standard SSH Extensions as defined in https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
 * 
 * @version $Id$
 *
 */
public enum SshExtension {
    NO_PRESENCE_REQUIRED("no-presence-required", new byte[0]), 
    PERMIT_X11_FORWARDING("permit-X11-forwarding", new byte[0]),
    PERMIT_AGENT_FORWARDING("permit-agent-forwarding", new byte[0]),
    PERMIT_PORT_FORWARDING("permit-port-forwarding", new byte[0]), 
    PERMIT_PTY("permit-pty", new byte[0]),
    PERMIT_USER_RC("permit-user-rc", new byte[0]);
    
    private final String label;
    private final byte[] value;
    
    private SshExtension(final String label, final byte[] value) {
        this.label = label;
        this.value = value;
    }
    
    public String getLabel() {
        return label;
    }
    
    public byte[] getValue() {
        return value;
    }
    
}
