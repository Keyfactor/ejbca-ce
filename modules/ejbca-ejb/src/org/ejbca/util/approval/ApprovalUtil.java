/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.approval;

import org.cesecore.util.LogRedactionUtils;
import org.ejbca.core.model.approval.ApprovalDataText;

import java.util.List;
import java.util.Map;

public class ApprovalUtil {


    /**
     * Check if the passed ApprovalDataText list has REDACT_PII flag in them.
     * @param approvalDataTexts list of ApprovalDataText
     */
    public static boolean isRedactPii(List<ApprovalDataText> approvalDataTexts) {
        for (ApprovalDataText text : approvalDataTexts) {
            if (text.getHeader().equalsIgnoreCase(ApprovalDataText.REDACT_PII) && text.getData().equalsIgnoreCase("TRUE")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Update the details map with data from ApprovalDataText and redact PII if necessary.
     * @param map       details to be used with audit logging
     * @param texts     list of ApprovalDataText
     * @return          updated details map
     */
    public static Map<String,Object> updateWithApprovalDataText(final Map<String, Object> map, final List<ApprovalDataText> texts) {
        final boolean redactPii = isRedactPii(texts);

        for (ApprovalDataText text : texts) {
            if (text.getHeader().equalsIgnoreCase(ApprovalDataText.SUBJECT_DN) || text.getHeader().equalsIgnoreCase(ApprovalDataText.SUBJECT_ALT_NAME)) {
                map.put(text.getHeader(), redactPii ? LogRedactionUtils.REDACTED_CONTENT : text.getData());
            } else {
                map.put(text.getHeader(), text.getData());
            }
        }

        return map;
    }
}
