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

package org.ejbca.config;

import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;

/**
 * Simple global cache holding protocol configuration settings from incoming Peer connection. Denied protocols will
 * override local configuration. By default, all protocols are enabled. Cache is updated when configuration is changed
 * from the CA or when a lost connection is reestablished.
 * 
 * @version $Id$
 *
 */
public enum AvailableProtocolsPeerCache {
    INSTANCE;
    
    private boolean allowAcme;
    private boolean allowCmp;
    private boolean allowEst;
    private boolean allowOcsp;
    private boolean allowScep;
    private boolean allowWebService;
    
    /** Allow all protocols by default */
    private AvailableProtocolsPeerCache() {
        allowAcme = true;
        allowCmp = true;
        allowEst = true;
        allowOcsp = true;
        allowScep = true;
        allowWebService = true;
    }

    /**
     * @param protocol supported by Ejbca @see {@link AvailableProtocols}
     * @return true if requested protocol is enabled for this peer. False otherwise.
     */
    public boolean isProtocolEnabled(String protocol) {
        if (protocol.equals(AvailableProtocols.ACME.getResource())) {
            return isAllowAcme();
        } else if (protocol.equals(AvailableProtocols.CMP.getResource())) {
            return isAllowCmp();
        } else if (protocol.equals(AvailableProtocols.EST.getResource())) {
            return isAllowEst();
        } else if (protocol.equals(AvailableProtocols.OCSP.getResource())) {
            return isAllowOcsp();
        } else if (protocol.equals(AvailableProtocols.SCEP.getResource())) {
            return isAllowScep();
        } else if (protocol.equals(AvailableProtocols.WS.getResource())) {
            return isAllowWebService();
        } 
        return false;
    }
    
    public boolean isAllowAcme() {return allowAcme;}

    public void setAllowAcme(boolean allowAcme) {this.allowAcme = allowAcme;}

    public boolean isAllowCmp() {return allowCmp;}

    public void setAllowCmp(boolean allowCmp) {this.allowCmp = allowCmp;}

    public boolean isAllowEst() {return allowEst;}

    public void setAllowEst(boolean allowEst) {this.allowEst = allowEst;}

    public boolean isAllowOcsp() {return allowOcsp;}

    public void setAllowOcsp(boolean allowOcsp) {this.allowOcsp = allowOcsp;}

    public boolean isAllowScep() {return allowScep;}

    public void setAllowScep(boolean allowScep) {this.allowScep = allowScep;}

    public boolean isAllowWebService() {return allowWebService;}

    public void setAllowWebService(boolean allowWebService) {this.allowWebService = allowWebService;}
}
