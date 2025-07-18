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
package org.ejbca.core;

import com.keyfactor.util.CertTools;
import org.ejbca.scp.publisher.ScpContainer;
import org.ejbca.scp.publisher.ScpContainerSigned;
import org.ejbca.scp.publisher.ScpContainerWrapper;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class YamlWriterUnitTest {
    private static final byte[] CONTAINER_CERT = """
            -----BEGIN CERTIFICATE-----
            MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE
            AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw
            ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD
            VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB
            hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy
            Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe
            ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G
            A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM
            MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw
            GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS
            5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c
            UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+
            XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==
            -----END CERTIFICATE-----
            """.getBytes(StandardCharsets.UTF_8);

    private static final String CONTAINER_YAML_SIGNATURE = """
            MIAGCSqGSIb3DQEHAqCAMIACAQExDTALBglghkgBZQMEAgEwgAYJKoZIhvcNAQcB
            oIAkgASCA+hjZXJ0aWZpY2F0ZTogfAogIC0tLS0tQkVHSU4gQ0VSVElGSUNBVEUt
            LS0tLQogIE1JSUNXekNDQWNTZ0F3SUJBZ0lJSk5ENkhhYTNOb0F3RFFZSktvWklo
            dmNOQVFFRkJRQXdMekVQTUEwR0ExVUUKICBBeE1HVkdWemRFTkJNUTh3RFFZRFZR
            UUtFd1pCYm1GVWIyMHhDekFKQmdOVkJBWVRBbE5GTUI0WERUQXlNREV3CiAgT0RB
            NU1URTFNbG9YRFRBME1ERXdPREE1TWpFMU1sb3dMekVQTUEwR0ExVUVBeE1HTWpV
            eE16UTNNUTh3RFFZRAogIFZRUUtFd1pCYm1GVWIyMHhDekFKQmdOVkJBWVRBbE5G
            TUlHZE1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTEFEQ0IKICBod0tCZ1FDUTNVQStu
            SUhFQ0o3OVM1VndJOFdGTEpiQUJ5QW5uMWsvSkVYMi9hMG5zYzIvSzNHWXpIRkl0
            UGp5CiAgQnY1elVjY1BMYlJta2RNbENEMXJPY2djUjltbW1qTVFyYldiV3AraVJn
            MFd5Q2t0V2Ivd1VTOHVOTnVHUVlRZQogIEFDbDExU0FIRlgrdTlKVVVmU3BwZzdT
            cHFGaFNnTWx2eVUvRmlHTFZFSERjaEpFZEdRSUJFYU9CZ1RCL01BOEcKICBBMVVk
            RXdFQi93UUZNQU1CQVFBd0R3WURWUjBQQVFIL0JBVURBd2VnQURBZEJnTlZIUTRF
            RmdRVXl4S0lMeEZNCiAgTU51ampObmJlRnBuUGdCNzZVWXdId1lEVlIwakJCZ3dG
            b0FVeTVrL2JLUTZUdHBUV2hzUFdGemFmT0ZnTG1zdwogIEd3WURWUjBSQkJRd0Vv
            RVFNalV4TXpRM1FHRnVZWFJ2YlM1elpUQU5CZ2txaGtpRzl3MEJBUVVGQUFPQmdR
            QVMKICA1d1NPSmhvVkpTYUVHSE1QdzZ0M2UrQ2JuRUw5WWg1R2xneFZBSkNtSXFo
            b1NjVE1pb3YzUXBEUkhPWmxaMTVjCiAgVWxxdWdSQnRPUnVBOXhuTGtyZHhZTkNI
            bVg2YUpUZmpkSVc2MStvL292UDB5ejZ1bEJrcWNLem9wQVpMaXJYKwogIFhTV2Yy
            dUk5bWlOdHhZTVZuYlExS1BkRUF0N1phM09RUjZ6Y1MwbEdLZz09CiAgLS0tLS1F
            TkQgQ0VSVElGSUNBVEUtLS0tLQpjZXJ0aWZpY2F0ZVByb2ZpbGU6IDM0CmNlcnRp
            ZmljYXRlUHJvZmlsZU5hbWU6IE15IENlcnRpZmljYXRlIFByb2ZpbGUgTmFtZQpj
            BIHbZXJ0aWZpY2F0ZVN0YXR1czogMgpjZXJ0aWZpY2F0ZVR5cGU6IDEKaXNzdWVy
            OiBpc3N1ZXJETgpsYXRlc3RWZXJzaW9uOiAwLjAKcmV2b2NhdGlvbkRhdGU6IDE3
            NTE4ODM3Mzg4OTMKcmV2b2NhdGlvblJlYXNvbjogMTIKc2VyaWFsTnVtYmVyOiAx
            MApzdWJqZWN0RG46IENOPTI1MTM0NyxPPUFuYVRvbSxDPVNFCnVwZGF0ZVRpbWU6
            IDE3NTE4ODM3Mzg4OTMKdXNlcm5hbWU6IG51bGwKAAAAAAAAoIAwggNnMIICT6AD
            AgECAhRWV3E51TtemMznmv7KQnTmGSOY8jANBgkqhkiG9w0BAQsFADA7MRUwEwYD
            VQQDDAxNYW5hZ2VtZW50Q0ExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UE
            BhMCU0UwHhcNMjUwNTA1MTM0NTE0WhcNMzUwNTAzMTM0NTEzWjA7MRUwEwYDVQQD
            DAxNYW5hZ2VtZW50Q0ExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMC
            U0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXPUQhOSFTF3XeQWw3
            OeGWTub7fKNTFHbIz3vz31mGZQ5ciEbwPbop1hZWXTQocC2JJ74VOVAdwAeNFH7S
            ztxVOsJfvREmD1f98l3Sv0WyMNPBRY+Afx+f7BqX4GFd+aWDurMOFBtVe9tnVU9Z
            O2+/xIJaDK87oUoLVjJjTNvOaSTEvOSTTwvaWiHdHS/+QTfcizSIbwVy80x8Dt18
            BCL+LJg27nNW+npcwx0Jv5Qp8dZKfMUfzqqCKf3KY0JtulR3hRcewH9Lecsty+hI
            3mHZ20HI+6uQJ8ztKz1SIYYfRlYYx4LlUzdHf2ZcxvxZP771zrxCMpPWQeXedhU0
            /Ft7AgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUyK17ukhU
            SF7pfzDR7icTQ1EP/XIwHQYDVR0OBBYEFMite7pIVEhe6X8w0e4nE0NRD/1yMA4G
            A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAUliuYPZh85zB7w8qMPhU
            jYdgEi6AlMzlOmyMMqqA0vn6k36k6L7plkHcJraqt2WDLVReJqgOrPfecuZJUEnd
            GiKcjJMLuTz3jGvZ1Fdgwl9bj9TSM4oKtaiLGwDwhzn6Y7LEw57HbRBcitjLT/7m
            go5HdhZY43Zj+1aB3zWq+snzM6ISDblUC7bqvJELDGKZ4ezxe+49t3XXL8DzmaCb
            z8ar7M4YBo8QayxKGj5Onbc0CqdkqDC3VUcu9ielCLsyHJOt+wOu9MvGtzIlKS6M
            YbHPAMD2+2bcbRywItgFh+71213zTKosugWCjQ3m3Lecvisjj3Q9zHUgBzVXjo11
            LgAAMYICFTCCAhECAQEwUzA7MRUwEwYDVQQDDAxNYW5hZ2VtZW50Q0ExFTATBgNV
            BAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UCFFZXcTnVO16YzOea/spCdOYZ
            I5jyMAsGCWCGSAFlAwQCAaCBljAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
            CSqGSIb3DQEJBTEPFw0yNTA3MDcxNDA1MDFaMCsGCSqGSIb3DQEJNDEeMBwwCwYJ
            YIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCBNeyiFDMIN
            Vn6HYGLbUEj6e8t/LRNWJSPBVXlp5Pz+EzANBgkqhkiG9w0BAQsFAASCAQBspz4C
            QmtUCewZB4ckdkMjoGC0qodwaL+FtdnzdunJEiwwpgzAwyQxpP9k0I6cse/IUUoC
            ueluf9EFclesdQksup57zOMRPshLYCxphvMMzYni9KNrG+HuYVBfn6wE89b/Wt1A
            hpaE5lg2lAV3GSz9GDYwtJXyaIZR5IpHBa8alp4pj6gGv0MvN5rL2OrMlE8eKKQA
            +VYV7EQiwmR0erkMPbaQPtg0DC89LHadZNC1nVWEV0mpmLFJUzEyOjNPoFjT+4ZN
            7QK1iCdLZ/8ID7kQ9BTEn2DfQ7UzNZRtgBpc/fFw/g1IP5ZIXt3KISrx0ZSZb4zH
            pxgtAchJwXvFbv40AAAAAAAA
            """;
    private static final byte[] CONTAINER_YAML = """
            data:
              certificate: |
                -----BEGIN CERTIFICATE-----
                MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE
                AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw
                ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD
                VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB
                hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy
                Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe
                ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G
                A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM
                MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw
                GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS
                5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c
                UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+
                XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==
                -----END CERTIFICATE-----
              certificateProfile: 34
              certificateProfileName: My Certificate Profile Name
              certificateStatus: 2
              certificateType: 1
              issuer: issuerDN
              latestVersion: 0.0
              revocationDate: 1751883738893
              revocationReason: 12
              serialNumber: 10
              subjectDn: CN=251347,O=AnaTom,C=SE
              updateTime: 1751883738893
              username: null
            signature: |
              MIAGCSqGSIb3DQEHAqCAMIACAQExDTALBglghkgBZQMEAgEwgAYJKoZIhvcNAQcB
              oIAkgASCA+hjZXJ0aWZpY2F0ZTogfAogIC0tLS0tQkVHSU4gQ0VSVElGSUNBVEUt
              LS0tLQogIE1JSUNXekNDQWNTZ0F3SUJBZ0lJSk5ENkhhYTNOb0F3RFFZSktvWklo
              dmNOQVFFRkJRQXdMekVQTUEwR0ExVUUKICBBeE1HVkdWemRFTkJNUTh3RFFZRFZR
              UUtFd1pCYm1GVWIyMHhDekFKQmdOVkJBWVRBbE5GTUI0WERUQXlNREV3CiAgT0RB
              NU1URTFNbG9YRFRBME1ERXdPREE1TWpFMU1sb3dMekVQTUEwR0ExVUVBeE1HTWpV
              eE16UTNNUTh3RFFZRAogIFZRUUtFd1pCYm1GVWIyMHhDekFKQmdOVkJBWVRBbE5G
              TUlHZE1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTEFEQ0IKICBod0tCZ1FDUTNVQStu
              SUhFQ0o3OVM1VndJOFdGTEpiQUJ5QW5uMWsvSkVYMi9hMG5zYzIvSzNHWXpIRkl0
              UGp5CiAgQnY1elVjY1BMYlJta2RNbENEMXJPY2djUjltbW1qTVFyYldiV3AraVJn
              MFd5Q2t0V2Ivd1VTOHVOTnVHUVlRZQogIEFDbDExU0FIRlgrdTlKVVVmU3BwZzdT
              cHFGaFNnTWx2eVUvRmlHTFZFSERjaEpFZEdRSUJFYU9CZ1RCL01BOEcKICBBMVVk
              RXdFQi93UUZNQU1CQVFBd0R3WURWUjBQQVFIL0JBVURBd2VnQURBZEJnTlZIUTRF
              RmdRVXl4S0lMeEZNCiAgTU51ampObmJlRnBuUGdCNzZVWXdId1lEVlIwakJCZ3dG
              b0FVeTVrL2JLUTZUdHBUV2hzUFdGemFmT0ZnTG1zdwogIEd3WURWUjBSQkJRd0Vv
              RVFNalV4TXpRM1FHRnVZWFJ2YlM1elpUQU5CZ2txaGtpRzl3MEJBUVVGQUFPQmdR
              QVMKICA1d1NPSmhvVkpTYUVHSE1QdzZ0M2UrQ2JuRUw5WWg1R2xneFZBSkNtSXFo
              b1NjVE1pb3YzUXBEUkhPWmxaMTVjCiAgVWxxdWdSQnRPUnVBOXhuTGtyZHhZTkNI
              bVg2YUpUZmpkSVc2MStvL292UDB5ejZ1bEJrcWNLem9wQVpMaXJYKwogIFhTV2Yy
              dUk5bWlOdHhZTVZuYlExS1BkRUF0N1phM09RUjZ6Y1MwbEdLZz09CiAgLS0tLS1F
              TkQgQ0VSVElGSUNBVEUtLS0tLQpjZXJ0aWZpY2F0ZVByb2ZpbGU6IDM0CmNlcnRp
              ZmljYXRlUHJvZmlsZU5hbWU6IE15IENlcnRpZmljYXRlIFByb2ZpbGUgTmFtZQpj
              BIHbZXJ0aWZpY2F0ZVN0YXR1czogMgpjZXJ0aWZpY2F0ZVR5cGU6IDEKaXNzdWVy
              OiBpc3N1ZXJETgpsYXRlc3RWZXJzaW9uOiAwLjAKcmV2b2NhdGlvbkRhdGU6IDE3
              NTE4ODM3Mzg4OTMKcmV2b2NhdGlvblJlYXNvbjogMTIKc2VyaWFsTnVtYmVyOiAx
              MApzdWJqZWN0RG46IENOPTI1MTM0NyxPPUFuYVRvbSxDPVNFCnVwZGF0ZVRpbWU6
              IDE3NTE4ODM3Mzg4OTMKdXNlcm5hbWU6IG51bGwKAAAAAAAAoIAwggNnMIICT6AD
              AgECAhRWV3E51TtemMznmv7KQnTmGSOY8jANBgkqhkiG9w0BAQsFADA7MRUwEwYD
              VQQDDAxNYW5hZ2VtZW50Q0ExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UE
              BhMCU0UwHhcNMjUwNTA1MTM0NTE0WhcNMzUwNTAzMTM0NTEzWjA7MRUwEwYDVQQD
              DAxNYW5hZ2VtZW50Q0ExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMC
              U0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXPUQhOSFTF3XeQWw3
              OeGWTub7fKNTFHbIz3vz31mGZQ5ciEbwPbop1hZWXTQocC2JJ74VOVAdwAeNFH7S
              ztxVOsJfvREmD1f98l3Sv0WyMNPBRY+Afx+f7BqX4GFd+aWDurMOFBtVe9tnVU9Z
              O2+/xIJaDK87oUoLVjJjTNvOaSTEvOSTTwvaWiHdHS/+QTfcizSIbwVy80x8Dt18
              BCL+LJg27nNW+npcwx0Jv5Qp8dZKfMUfzqqCKf3KY0JtulR3hRcewH9Lecsty+hI
              3mHZ20HI+6uQJ8ztKz1SIYYfRlYYx4LlUzdHf2ZcxvxZP771zrxCMpPWQeXedhU0
              /Ft7AgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUyK17ukhU
              SF7pfzDR7icTQ1EP/XIwHQYDVR0OBBYEFMite7pIVEhe6X8w0e4nE0NRD/1yMA4G
              A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAUliuYPZh85zB7w8qMPhU
              jYdgEi6AlMzlOmyMMqqA0vn6k36k6L7plkHcJraqt2WDLVReJqgOrPfecuZJUEnd
              GiKcjJMLuTz3jGvZ1Fdgwl9bj9TSM4oKtaiLGwDwhzn6Y7LEw57HbRBcitjLT/7m
              go5HdhZY43Zj+1aB3zWq+snzM6ISDblUC7bqvJELDGKZ4ezxe+49t3XXL8DzmaCb
              z8ar7M4YBo8QayxKGj5Onbc0CqdkqDC3VUcu9ielCLsyHJOt+wOu9MvGtzIlKS6M
              YbHPAMD2+2bcbRywItgFh+71213zTKosugWCjQ3m3Lecvisjj3Q9zHUgBzVXjo11
              LgAAMYICFTCCAhECAQEwUzA7MRUwEwYDVQQDDAxNYW5hZ2VtZW50Q0ExFTATBgNV
              BAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UCFFZXcTnVO16YzOea/spCdOYZ
              I5jyMAsGCWCGSAFlAwQCAaCBljAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
              CSqGSIb3DQEJBTEPFw0yNTA3MDcxNDA1MDFaMCsGCSqGSIb3DQEJNDEeMBwwCwYJ
              YIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCBNeyiFDMIN
              Vn6HYGLbUEj6e8t/LRNWJSPBVXlp5Pz+EzANBgkqhkiG9w0BAQsFAASCAQBspz4C
              QmtUCewZB4ckdkMjoGC0qodwaL+FtdnzdunJEiwwpgzAwyQxpP9k0I6cse/IUUoC
              ueluf9EFclesdQksup57zOMRPshLYCxphvMMzYni9KNrG+HuYVBfn6wE89b/Wt1A
              hpaE5lg2lAV3GSz9GDYwtJXyaIZR5IpHBa8alp4pj6gGv0MvN5rL2OrMlE8eKKQA
              +VYV7EQiwmR0erkMPbaQPtg0DC89LHadZNC1nVWEV0mpmLFJUzEyOjNPoFjT+4ZN
              7QK1iCdLZ/8ID7kQ9BTEn2DfQ7UzNZRtgBpc/fFw/g1IP5ZIXt3KISrx0ZSZb4zH
              pxgtAchJwXvFbv40AAAAAAAA
            """.getBytes(StandardCharsets.UTF_8);

    @Test
    public void shouldConvertScpPublisherSignedToYaml() throws Exception {
        final Certificate cert = CertTools.getCertfromByteArray(CONTAINER_CERT, Certificate.class);
        final ScpContainer scpContainer = new ScpContainer()
                .setCertificateStatus(2)
                .setIssuer("issuerDN")
                .setRevocationDate(1751883738893L)
                .setRevocationReason(12)
                .setCertificateProfile(34)
                .setCertificateType(1)
                .setUpdateTime(1751883738893L)
                .setSerialNumber(BigInteger.TEN)
                .setCertificate(cert);

        final ScpContainerWrapper containerWrapper = new ScpContainerWrapper(scpContainer);
        containerWrapper.setCertificateProfileName("My Certificate Profile Name");
        final ScpContainerSigned signedContainer = new ScpContainerSigned(containerWrapper);
        signedContainer.setSignature(CONTAINER_YAML_SIGNATURE);

        final byte[] result = YamlWriter.exportToYamlBytes(signedContainer);

        assertNotNull(result);
        assertEquals(new String(CONTAINER_YAML), new String(result));
    }

    @Test
    public void shouldConvertScpPublisherSignedFromYaml() {
        final String pemCertificate = new String(CONTAINER_CERT);
        final ScpContainerSigned resultContainer =
                YamlWriter.importFromYamlBytes(CONTAINER_YAML, ScpContainerSigned.class);

        assertNotNull(resultContainer);
        assertEquals(CONTAINER_YAML_SIGNATURE, resultContainer.getSignature());
        assertEquals(pemCertificate, resultContainer.getData().getCertificate());
        assertEquals("CN=251347,O=AnaTom,C=SE", resultContainer.getData().getSubjectDn());
        assertEquals(BigInteger.TEN, resultContainer.getData().getSerialNumber());
        assertEquals(2, resultContainer.getData().getCertificateStatus());
        assertEquals("issuerDN", resultContainer.getData().getIssuer());
        assertEquals(12, resultContainer.getData().getRevocationReason());
        assertEquals(1751883738893L, resultContainer.getData().getRevocationDate());
        assertEquals(34, resultContainer.getData().getCertificateProfile());
        assertEquals("My Certificate Profile Name", resultContainer.getData().getCertificateProfileName());
        assertEquals(1, resultContainer.getData().getCertificateType());
        assertEquals(1751883738893L, resultContainer.getData().getUpdateTime());
    }

}
