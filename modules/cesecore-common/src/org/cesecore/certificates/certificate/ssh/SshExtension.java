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

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Standard SSH Extensions as defined in https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
 *
 * @version $Id$
 */
public enum SshExtension {
    NO_TOUCH_REQUIRED("no-touch-required", new byte[0]),
    PERMIT_X11_FORWARDING("permit-X11-forwarding", new byte[0]),
    PERMIT_AGENT_FORWARDING("permit-agent-forwarding", new byte[0]),
    PERMIT_PORT_FORWARDING("permit-port-forwarding", new byte[0]),
    PERMIT_PTY("permit-pty", new byte[0]),
    PERMIT_USER_RC("permit-user-rc", new byte[0]);

    public static final Map<String,String> EXTENSIONS_MAP;
    static {
        final Map<String,String> extensions = new LinkedHashMap<>();
        for (final SshExtension sshExtension : values()) {
            extensions.put(sshExtension.getLabel(), new String(sshExtension.getValue(), StandardCharsets.UTF_8));
        }
        EXTENSIONS_MAP = Collections.unmodifiableMap(extensions);
    }

    private final String label;
    private final byte[] value;

    SshExtension(final String label, final byte[] value) {
        this.label = label;
        this.value = value;
    }

    public String getLabel() {
        return label;
    }

    public byte[] getValue() {
        return value;
    }
    
    public static SshExtension findbyLabel(final String label) {
        for(SshExtension sshExtension : SshExtension.values()) {
            if(sshExtension.getLabel().equalsIgnoreCase(label)) {
                return sshExtension;
            }
        }
        return null;
    }

}
