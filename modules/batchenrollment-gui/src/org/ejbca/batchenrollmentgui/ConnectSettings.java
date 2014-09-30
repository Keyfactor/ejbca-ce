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
package org.ejbca.batchenrollmentgui;

/**
 * Holds the connection settings.
 * 
 * @author markus
 * @version $Id$
 */
public class ConnectSettings {
    
    private String url;
    private String truststoreType;
    private String truststoreFile;
    private char[] truststorePassword;
    private String keystoreType;
    private String keystoreFile;
    private char[] keystorePassword;

    public ConnectSettings() {
        
    }
    
    public ConnectSettings(final String url, final String truststoreType,
            final String truststoreFile, final char[] truststorePassword,
            final String keystoreType, final String keystoreFile,
            final char[] keystorePassword) {
        this.url = url;
        this.truststoreType = truststoreType;
        this.truststoreFile = truststoreFile;
        this.truststorePassword = truststorePassword;
        this.keystoreType = keystoreType;
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
    }

    public String getKeystoreFile() {
        return keystoreFile;
    }

    public char[] getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getTruststoreFile() {
        return truststoreFile;
    }

    public char[] getTruststorePassword() {
        return truststorePassword;
    }

    public String getTruststoreType() {
        return truststoreType;
    }

    public String getUrl() {
        return url;
    }

    public void setKeystoreFile(String keystoreFile) {
        this.keystoreFile = keystoreFile;
    }

    public void setKeystorePassword(char[] keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    public void setTruststoreFile(String truststoreFile) {
        this.truststoreFile = truststoreFile;
    }

    public void setTruststorePassword(char[] truststorePassword) {
        this.truststorePassword = truststorePassword;
    }

    public void setTruststoreType(String truststoreType) {
        this.truststoreType = truststoreType;
    }

    public void setUrl(String url) {
        this.url = url;
    }

}
