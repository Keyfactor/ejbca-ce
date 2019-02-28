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

package org.ejbca.ui.web.admin.cainterface;

/**
 * 
 * @version $Id$
 *
 */
public class CaGuiInfo {
        
        private CaInfoProperty caName;
        private CaInfoProperty subjectDn;
        private CaInfoProperty alternativeName;
        private CaInfoProperty caType;
        private CaInfoProperty expireTime;
        private CaInfoProperty status;
        private CaInfoProperty description;
        private CaInfoProperty crlPeriod;
        private CaInfoProperty crlIssueInterval;
        private CaInfoProperty crlOverlapTime;
        private CaInfoProperty deltaCrlPeriod;
        private CaInfoProperty crlPublishers;
        private CaInfoProperty validators;
        private CaInfoProperty ocsp;
        
        public CaInfoProperty getCaName() {
            return caName;
        }
        public void setCaName(final CaInfoProperty caName) {
            this.caName = caName;
        }
        public CaInfoProperty getSubjectDn() {
            return subjectDn;
        }
        public void setSubjectDn(final CaInfoProperty subjectDn) {
            this.subjectDn = subjectDn;
        }
        public CaInfoProperty getAlternativeName() {
            return alternativeName;
        }
        public void setAlternativeName(final CaInfoProperty alternativeName) {
            this.alternativeName = alternativeName;
        }
        public CaInfoProperty getCaType() {
            return caType;
        }
        public void setCaType(final CaInfoProperty caType) {
            this.caType = caType;
        }
        public CaInfoProperty getExpireTime() {
            return expireTime;
        }
        public void setExpireTime(final CaInfoProperty expireTime) {
            this.expireTime = expireTime;
        }
        public CaInfoProperty getStatus() {
            return status;
        }
        public void setStatus(final CaInfoProperty status) {
            this.status = status;
        }
        public CaInfoProperty getDescription() {
            return description;
        }
        public void setDescription(final CaInfoProperty description) {
            this.description = description;
        }
        public CaInfoProperty getCrlPeriod() {
            return crlPeriod;
        }
        public void setCrlPeriod(final CaInfoProperty crlPeriod) {
            this.crlPeriod = crlPeriod;
        }
        public CaInfoProperty getCrlIssueInterval() {
            return crlIssueInterval;
        }
        public void setCrlIssueInterval(final CaInfoProperty crlIssueInterval) {
            this.crlIssueInterval = crlIssueInterval;
        }
        public CaInfoProperty getCrlOverlapTime() {
            return crlOverlapTime;
        }
        public void setCrlOverlapTime(final CaInfoProperty crlOverlapTime) {
            this.crlOverlapTime = crlOverlapTime;
        }
        public CaInfoProperty getDeltaCrlPeriod() {
            return deltaCrlPeriod;
        }
        public void setDeltaCrlPeriod(final CaInfoProperty deltaCrlPeriod) {
            this.deltaCrlPeriod = deltaCrlPeriod;
        }
        public CaInfoProperty getCrlPublishers() {
            return crlPublishers;
        }
        public void setCrlPublishers(final CaInfoProperty crlPublishers) {
            this.crlPublishers = crlPublishers;
        }
        public CaInfoProperty getValidators() {
            return validators;
        }
        public void setValidators(final CaInfoProperty validators) {
            this.validators = validators;
        }
        public CaInfoProperty getOcsp() {
            return ocsp;
        }
        public void setOcsp(final CaInfoProperty ocsp) {
            this.ocsp = ocsp;
        }
    }