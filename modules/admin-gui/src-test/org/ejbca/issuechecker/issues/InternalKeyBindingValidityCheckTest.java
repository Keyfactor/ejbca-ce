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

package org.ejbca.issuechecker.issues;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.junit.Test;

import com.google.common.collect.ImmutableList;
import com.keyfactor.util.CertTools;

/**
 * Unit tests for {@link InternalKeyBindingValidityCheck}.
 * 
 * @version $Id $
 */
public class InternalKeyBindingValidityCheckTest {
    @Test
    public void getTickets() throws Exception {
        final String expiredCert = "-----BEGIN CERTIFICATE-----\n" + 
                "MIIDgDCCAmigAwIBAgIQJF3XD0RMFNXiksdfSkABJjANBgkqhkiG9w0BAQsFADBW\n" + 
                "MSAwHgYDVQQDDBdTdG9ybWh1YiBSU0EgU3RhZ2luZyBHMTElMCMGA1UECgwcU3Rv\n" + 
                "cm1odWIgVHJ1c3QgU2VydmljZXMgTHRkLjELMAkGA1UEBhMCU0UwHhcNMTkwNjE4\n" + 
                "MTQ0NTQyWhcNMTkwNjI1MTQ0NTQyWjAYMRYwFAYDVQQDDA1PQ1NQIFAxMSBUZXN0\n" + 
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9JdRvaDjGlJkmP1kDioX\n" + 
                "NWb10N91AbJvjCQTO3KngIjq+d0y3RBS0FaUjN7kNKPvn69rjWOJrWwd7AWg2SXx\n" + 
                "AmGBTqfh3kDRhpD+MRR0CRoW+SE5bXwf7Rpz1K5jb+ly6O6yfrv6FLSkjyv/D82z\n" + 
                "R6YZKSGzep+4DoakXGmB0bFrupmXDvUzzYGSVK4gxnENo2UZsJod1r/EuaiiQhSl\n" + 
                "CdLQzmn0kSJV/9eBrMSiKCABNdp/L6ldkPWGTkDJGj7Z/XKNOIK6qzxBvCEGLI99\n" + 
                "pcpO8S5ahPhePpdPsIyM7vKlu6U7rrNKYR4ntrwWjm7fhh+B51SwK9M73lazjKJs\n" + 
                "1wIDAQABo4GHMIGEMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUCxOHWnPRmyy+\n" + 
                "ZEkftX24n20vrX0wDwYJKwYBBQUHMAEFBAIFADATBgNVHSUEDDAKBggrBgEFBQcD\n" + 
                "CTAdBgNVHQ4EFgQUvD9zxWwkGBC6mOFuFOrPrvqgvXcwDgYDVR0PAQH/BAQDAgeA\n" + 
                "MA0GCSqGSIb3DQEBCwUAA4IBAQBinTWISlS1z1ZAIeq2wMXlifek5tyy4wzF86tL\n" + 
                "mL67rrq+9mfTJySFvwPp8ATXH+FZKguutAHlRBw2bqKLGfpM/UMwGVGwxJ2/Rrke\n" + 
                "NKOZX93RB5F+djch/f7fYABzZYBt2CY8O3uhObL/XQGAXaKjsDiDIh5MXyUelTA6\n" + 
                "qkk59pIzW4xmu2ogOZj7ylI4ApYPn5mRydXjm9CrhmieZbKKVGfbEmVtw0r7bYvO\n" + 
                "n0LnzSCI+t8xODi+9D0XTr5FK9WW4HeVU2jE7i5XHSX2NPzw/H2/36BCiscDtuoy\n" + 
                "WPoT0g5gHhyLm+64oOUeF3EOyI7Oyt/5Gy2KK9e+bh5ovMH2\n" + 
                "-----END CERTIFICATE-----";
        final String notExpiredCert = "-----BEGIN CERTIFICATE-----\n" + 
                "MIIFdTCCA12gAwIBAgIIf5mmvgUFvKswDQYJKoZIhvcNAQELBQAwSDELMAkGA1UE\n" + 
                "BhMCU0UxHjAcBgNVBAoMFVByaW1lS2V5IFNvbHV0aW9ucyBBQjEZMBcGA1UEAwwQ\n" + 
                "Q1QgTG9nIFRlc3QgUm9vdDAeFw0xODAzMDUxMzM2MzdaFw0zODAyMjgxMzM2Mzda\n" + 
                "MEgxCzAJBgNVBAYTAlNFMR4wHAYDVQQKDBVQcmltZUtleSBTb2x1dGlvbnMgQUIx\n" + 
                "GTAXBgNVBAMMEENUIExvZyBUZXN0IFJvb3QwggIiMA0GCSqGSIb3DQEBAQUAA4IC\n" + 
                "DwAwggIKAoICAQC9EtlNghGlkLXu3vC2PcfdK6GmJbeEgLjgwz7BiwKahdQE2cfX\n" + 
                "Zrz53YcDZ1uH/OiGPvz4B1nJpBfqxgfByPb4iAyjGfZPbwcs408GiW1NbblOyrz7\n" + 
                "AkucwgetqVeAKmpTlPr2x9fu2zfb8J/BDU9cdn1Mb9Xznx4h73100UI8vR9s0KM9\n" + 
                "HjQzlaD/kMr4yX5cPI9os53hJ0oDUAXhQif6nq15mCgFJbk2v8T26lDhahOqBp1X\n" + 
                "dIXyeGOP1YB9t8TiMzVvIBx4UXjl0uCxwSXDm8BpfgnS/Q89ni6KYxBI6JZQmo0V\n" + 
                "zFNNehAE0m9jnJAhXKH8hqqw2wKa/B1eZ0tYsOJgg0weHVekpBfJr2IM6OS6WAOX\n" + 
                "cIGL4+MEax+1kIqtAFQKVO7+k2MHhxGyG9tNDYXdBoYAgTIC1GEj6Utcv+OCaY7q\n" + 
                "6k90xkKbEhHF65bZBl0H+zMVpKozIXaiHuYBJ5dzrqH6mWm0z3oRIYt2SuZiEbMO\n" + 
                "NYGcILHjTsPHFccr4ygHQExkYX3LQTLBxiULwkchPamGdUjqBFgAG8JbcisP76yo\n" + 
                "o6skfTgEhWjmBIhSoRHvhkIIB9zqlF/qIJymlK7QGgdp1ZxDNNIrcq9RsgvWvZRW\n" + 
                "grC1ffLlV5oG7t9nyr33hODj3pK8B/S9LHUY4c0V2G5vgyahKkeFg/idQwIDAQAB\n" + 
                "o2MwYTAdBgNVHQ4EFgQUWkyxsq+pPgkobrn4bHjVaqCBKNEwDwYDVR0TAQH/BAUw\n" + 
                "AwEB/zAfBgNVHSMEGDAWgBRaTLGyr6k+CShuufhseNVqoIEo0TAOBgNVHQ8BAf8E\n" + 
                "BAMCAYYwDQYJKoZIhvcNAQELBQADggIBAAtOrCFtI+wfTTFWdP0r8KC/jV5jwXXw\n" + 
                "pBfqcWOeidFAtph/cNL+iEVYaRQrnI1nz0yttUTzSYSLzEW62m5CaJ9CVWTsf1x9\n" + 
                "qNZbW6tOlxLFvHzoACg7OdS7jHATYV3D2GyvAb9e/vCNVEFYMmFoT1c/1CwkLJEb\n" + 
                "B46VlHTc9Fk2yoySBi/Vm6feZddm5cw/1UvKqrnQQWsCa1Ov/A30YojVCW7Oc85M\n" + 
                "J2cfpAr/qRCAVzQnt+ygup2M3hdtsgJtW9gnkgE2sQB+ndQcF33OoaM6l5af/Kka\n" + 
                "Lhnna9AzssLVP9lAthLKSh0dna/cxbbbeJdY0dcD1CKfaTGIKmwG7KGJunkq7iZ6\n" + 
                "K0K4a8lvorosvhu9jXoJvA5vAndTukrIbC7/P//Y13vDaE/sryMXtIz3cpWQ3NAE\n" + 
                "wxYC+vhPJ0f11Y1EQrzUOUU74mLDd8pWgBmyzWUJhtCmJR6/Dju8Jv3IkplHJq9/\n" + 
                "icwRa5xNKgFlysPtXzkinFQi6EsEfc7IBPYqWq7lLLCmitxqbabg1J1HnAAn54VZ\n" + 
                "GQ8atIAtj0pv45huYswvZdlgBrgTmAhHPQZKSBAqwJeOJULpU5dqmey72RXLpMu0\n" + 
                "YCAjNGOyy0txxvh/wVzmTPsu/hp83kSl1wtAELhGPnidkLJqqXKYuK4uMEiZGbnR\n" + 
                "XZ1LK9Vj0z3S\n" + 
                "-----END CERTIFICATE-----";
        
        final InternalKeyBindingDataSessionLocal internalKeyBindingSession = createMock(InternalKeyBindingDataSessionLocal.class);
        final CertificateStoreSessionLocal certificateSession = createMock(CertificateStoreSessionLocal.class);
        final AuthorizationSessionLocal authorizationSession = createMock(AuthorizationSessionLocal.class);
        
        final InternalKeyBinding notActice = createNiceMock(InternalKeyBinding.class);
        final InternalKeyBinding notExpired = createNiceMock(InternalKeyBinding.class);
        final InternalKeyBinding expired = createNiceMock(InternalKeyBinding.class);

        expect(internalKeyBindingSession.getIds(null)).andReturn(ImmutableList.of(1, 2, 3)).anyTimes();
        expect(internalKeyBindingSession.getInternalKeyBinding(1)).andReturn(notActice).anyTimes();
        expect(internalKeyBindingSession.getInternalKeyBinding(2)).andReturn(notExpired).anyTimes();
        expect(internalKeyBindingSession.getInternalKeyBinding(3)).andReturn(expired).anyTimes();

        expect(notActice.getStatus()).andReturn(InternalKeyBindingStatus.DISABLED).anyTimes();
        expect(notExpired.getStatus()).andReturn(InternalKeyBindingStatus.ACTIVE).anyTimes();
        expect(expired.getStatus()).andReturn(InternalKeyBindingStatus.ACTIVE).anyTimes();

        expect(notActice.getCertificateId()).andReturn(null).anyTimes();
        expect(notExpired.getCertificateId()).andReturn("notExpiredCert").anyTimes();
        expect(expired.getCertificateId()).andReturn("expiredCert").anyTimes();
        
        expect(expired.getName()).andReturn("EXPIRED").once();

        expect(certificateSession.getCertificateData("notExpiredCert"))
                .andReturn(new CertificateDataWrapper(CertTools.getCertfromByteArray(notExpiredCert.getBytes(), X509Certificate.class), null, null))
                .anyTimes();
        expect(certificateSession.getCertificateData("expiredCert"))
                .andReturn(new CertificateDataWrapper(CertTools.getCertfromByteArray(expiredCert.getBytes(), X509Certificate.class), null, null))
                .anyTimes();

        replay(internalKeyBindingSession);
        replay(certificateSession);
        replay(authorizationSession);

        replay(notActice);
        replay(notExpired);
        replay(expired);

        final List<String> ticketDescriptions = new InternalKeyBindingValidityCheck(
                    internalKeyBindingSession, 
                    certificateSession,
                    authorizationSession
                )
                .getTickets()
                .stream()
                .map(ticket -> ticket.getTicketDescription().toString())
                .sorted()
                .collect(Collectors.toList());
        
        verify(internalKeyBindingSession);
        verify(certificateSession);
        verify(authorizationSession);

        assertEquals("Wrong tickets: " + ticketDescriptions, 1, ticketDescriptions.size());
        assertEquals("(INTERNAL_KEY_BINDING_VALIDITY_CHECK_TICKET_DESCRIPTION, EXPIRED)", ticketDescriptions.get(0));
    }

    @Test
    public void databaseValue() {
        assertEquals("The database value is not allowed to change.", "InternalKeyBindingValidityCheck",
                new InternalKeyBindingValidityCheck(null, null, null).getDatabaseValue());
    }
}
