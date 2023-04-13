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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.List;

public class RaCertificateDataOnRenew implements Serializable {

    private static final long serialVersionUID = 1L;

    private String caName;
    private String endEntityProfileName;
    private String certificateProfileName;
    private String username;
    private boolean revoked;
    private boolean notificationConfigured;
    private boolean keyAlgorithmPreSet;
    private List<String> availableKeyAlgorithms;
    private List<Integer> availableBitLengths;
    private List<String> availableEcCurves;

    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public boolean isNotificationConfigured() {
        return notificationConfigured;
    }

    public void setNotificationConfigured(boolean notificationConfigured) {
        this.notificationConfigured = notificationConfigured;
    }

    public boolean isKeyAlgorithmPreSet() {
        return keyAlgorithmPreSet;
    }

    public void setKeyAlgorithmPreSet(boolean keyAlgorithmPreSet) {
        this.keyAlgorithmPreSet = keyAlgorithmPreSet;
    }

    public List<String> getAvailableKeyAlgorithms() {
        return availableKeyAlgorithms;
    }

    public void setAvailableKeyAlgorithms(List<String> availableKeyAlgorithms) {
        this.availableKeyAlgorithms = availableKeyAlgorithms;
    }

    public List<Integer> getAvailableBitLengths() {
        return availableBitLengths;
    }

    public void setAvailableBitLengths(List<Integer> availableBitLengths) {
        this.availableBitLengths = availableBitLengths;
    }

    public List<String> getAvailableEcCurves() {
        return availableEcCurves;
    }

    public void setAvailableEcCurves(List<String> availableEcCurves) {
        this.availableEcCurves = availableEcCurves;
    }
}
