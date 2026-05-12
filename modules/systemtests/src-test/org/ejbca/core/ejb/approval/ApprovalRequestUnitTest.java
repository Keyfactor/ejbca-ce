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
package org.ejbca.core.ejb.approval;

import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AcmeKeyChangeApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AcmeNewAccountApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class ApprovalRequestUnitTest {

    private static List<Object> getApprovalRequests() {
        return Arrays.asList(
                new AcmeKeyChangeApprovalRequest(),
                new AcmeNewAccountApprovalRequest(),
                new ActivateCATokenApprovalRequest(),
                new AddEndEntityApprovalRequest(),
                new ChangeStatusEndEntityApprovalRequest(),
                new EditEndEntityApprovalRequest(),
                new KeyRecoveryApprovalRequest(),
                new RevocationApprovalRequest(),
                new AccumulativeApprovalProfile(),
                new PartitionedApprovalProfile()
        );
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        final var allObjects = new ArrayList<Object[]>();
        for (var approvalRequest : getApprovalRequests()) {
            allObjects.add(new Object[]{ approvalRequest });
        }
        return allObjects;
    }

    private final ApprovalData approvalData;
    private final Object object;

    public ApprovalRequestUnitTest(final Object object) {
        this.approvalData = new ApprovalData();
        this.object = object;
    }

    InputStream getInputStream() throws IOException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (final ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(object);
        }
        final byte[] bytes = byteArrayOutputStream.toByteArray();
        return new ByteArrayInputStream(bytes);
    }

    @Before
    public void setUp() {
    }

    @Test
    public void testReadObjectWithLookAhead() throws IOException, ClassNotFoundException {
        // Given
        final var inputStream = getInputStream();

        // When
        var actual = approvalData.readObjectWithLookAhead(inputStream);

        // Then
        assertEquals(object, actual);
    }

}
