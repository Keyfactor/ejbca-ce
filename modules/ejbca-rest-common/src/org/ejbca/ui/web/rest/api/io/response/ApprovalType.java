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

package org.ejbca.ui.web.rest.api.io.response;

import java.util.HashMap;
import java.util.Map;
import org.ejbca.core.model.approval.ApprovalDataVO;

public enum ApprovalType {
    ADD_END_ENTITY(ApprovalDataVO.APPROVALTYPE_ADDENDENTITY, "Add End Entity"),
    EDIT_END_ENTITY(ApprovalDataVO.APPROVALTYPE_EDITENDENTITY, "Edit End Entity"),
    REVOKE_END_ENTITY(ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, "Revoke End Entity"),
    CHANGE_STATUS_END_ENTITY(ApprovalDataVO.APPROVALTYPE_CHANGESTATUSENDENTITY, "Change Status of End Entity"),
    KEY_RECOVERY(ApprovalDataVO.APPROVALTYPE_KEYRECOVERY, "Key Recovery"),
    REVOKE_CERTIFICATE(ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, "Revoke Certificate"),
    REVOKE_AND_DELETE_END_ENTITY(ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY, "Revoke and Delete End Entity"),
    ACME_ACCOUNT_KEY_CHANGE(ApprovalDataVO.APPROVALTYPE_ACME_ACCOUNT_KEYCHANGE, "ACME Account Key Change"),
    ACME_ACCOUNT_REGISTRATION(ApprovalDataVO.APPROVALTYPE_ACME_ACCOUNT_REGISTRATION, "ACME Account Registration"),
    ACTIVATE_CA_TOKEN(ApprovalDataVO.APPROVALTYPE_ACTIVATECATOKEN, "Activate CA Token");

    private final int typeCode;
    private final String description;
    private static final Map<Integer, ApprovalType> BY_CODE = new HashMap<>();

    static {
        for (ApprovalType type : values()) {
            BY_CODE.put(type.typeCode, type);
        }
    }

    ApprovalType(int typeCode, String description) {
        this.typeCode = typeCode;
        this.description = description;
    }

    public static String getNameByCode(int code) {
        ApprovalType type = BY_CODE.get(code);
        return type != null ? type.description : "Unknown Type (" + code + ")";
    }

    public int getTypeCode() {
        return typeCode;
    }

    public String getDescription() {
        return description;
    }
}
