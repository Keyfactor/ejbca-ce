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
package org.ejbca.ui.cli.ca;

/**
 * System test for {@link CaImportMsCaCertificates}.
 * 
 * @version $Id: $
 */
public class CaImportMsCaCertificatesTest {
    /**
    Schema:
    Column Name                   Localized Name                Type    MaxLength
    ----------------------------  ----------------------------  ------  ---------
    UPN                           User Principal Name           String  2048 -- Indexed
    CertificateTemplate           Certificate Template          String  254 -- Indexed
    Request.Disposition           Request Disposition           Long    4 -- Indexed
    RawCertificate                Binary Certificate            Binary  16384
    
    Row 1:
    User Principal Name: EMPTY
    Certificate Template: "1.3.6.1.4.1.311.21.8.6486083.1737355.11158168.1694049.3365734.200.4422329.5727551" EFOSFunctionClientServerAuth_SAT
    Request Disposition: 0x15 (21) -- Revoked
    Binary Certificate:
    -----BEGIN CERTIFICATE-----
    MIIGCTCCA/GgAwIBAgITcgAAAAML4lyOAKFaMQAAAAAAAzANBgkqhkiG9w0BAQsF
    ADBqMQswCQYDVQQGEwJTRTEoMCYGA1UEChMfU3dlZGlzaCBTb2NpYWwgSW5zdXJh
    bmNlIEFnZW5jeTExMC8GA1UEAxMoU3dlZGlzaCBQdWJsaWMgU2VjdG9yIEZ1bmN0
    aW9uIENBIFNBVCB2MTAeFw0xNzEyMjAxMzE0MzRaFw0xODEyMjAxMzE0MzBaMBgx
    FjAUBgNVBAMTDXRlc3QuaW5lcmEuc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
    ggEKAoIBAQCkHiaN9vXit0+D2+Q+e1kZwcTn1TY3/0VxzhX/zueY02N0mOvTXQOL
    BiPcFfjw7Gx6Z840gcH0uc7GVaxxAMa9cP+W07LByvUt4a2tnJebxoaZB5i7h1M3
    7M2bwFdSCu/jXFzOvaIODARuQjwr8TnrnPcSr7HEG/UliDFWH1m5B0SrzJvVMxS0
    YxqINN5p7WMbA8MRgV2u8aGwiucvkZAKvAxEa/fawm9zR++d5lVRhXismzq/RoPM
    z7H+1Rx7sZ6vyK3wAVn98OZ7FeKIBgp+MqLn3mLwKuqvCuB+PIIlM6EfmhYc4aQk
    FWY94Wld3ZoJp9mpEPhXdCP+955ZijlHAgMBAAGjggH4MIIB9DALBgNVHQ8EBAMC
    BaAwHQYDVR0OBBYEFCjyL0BfrWA+Ks6EXgYVNFa1ITEqMB8GA1UdIwQYMBaAFBTi
    p1Sy2PTcoYp8gas0BGxKwxzWME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9jcmxz
    YXQuZWZvcy5zZS9Td2VkaXNoUHVibGljU2VjdG9yRnVuY3Rpb25DQVNBVHYxLmNy
    bDB8BggrBgEFBQcBAQRwMG4wSAYIKwYBBQUHMAKGPGh0dHA6Ly9haWFzYXQuZWZv
    cy5zZS9Td2VkaXNoUHVibGljU2VjdG9yRnVuY3Rpb25DQVNBVHYxLmNydDAiBggr
    BgEFBQcwAYYWaHR0cDovL29jc3BzYXQuZWZvcy5zZTA8BgkrBgEEAYI3FQcELzAt
    BiUrBgEEAYI3FQiDi/BD6oULhamFGOeyYYHNtmaBSIKN9TmC3co/AgFkAgFAMCcG
    A1UdJQQgMB4GCCsGAQUFBwMBBggrBgEFBQcDBAYIKwYBBQUHAwIwMwYJKwYBBAGC
    NxUKBCYwJDAKBggrBgEFBQcDATAKBggrBgEFBQcDBDAKBggrBgEFBQcDAjA8BgNV
    HSAENTAzMDEGBmeBDAECAjAnMCUGCCsGAQUFBwIBFhlodHRwOi8vcmVwb3NpdG9y
    eS5lZm9zLnNlMA0GCSqGSIb3DQEBCwUAA4ICAQAhfhWMY5glWSkGVhSr5nFnNbug
    qJQpbh1GfmOq6XlneytbeCkaUt1pC1mxM+6xUKd4nMon3rOIn9Mj933IYJbdgH98
    EKSChqmo3nw0GD1O8KJNfMsRGB5jnvg0yO2vvkB493xbl2HyKPgcnOVxsAVpjWu+
    SzV7kqYXKLT/Rk9Piao1Z2dOPilL1P3JfX2sk2fiRDF2/S8Y58+UB9LwcSbLcp8r
    aJpVkslDy2L+gvcOaXBI1UGhufmJ6p4Kjs3STupfWH5dmHuwA/UYCvyoWcAcsPkm
    HJ3oRZv3eT8YXeVNAaR0B1ph2B160wJZLsLasH8JA9vkon6D4UIzmt57aVb38wQb
    nHlgN25jFZkzf7PFOaZapicDbA/GdKR/LFh3sXkwao8RqRUg3IJb/nGl69szbzMZ
    HyKU+36SUXkdYiqlOqtYpS8ZUE1huYZ0p31MSc0+7Ur0EJK3Aj5CH3kDuJsTgEvs
    fkz1AeuZc5F2G++HJPdN/FBukehrxUrHSTXnTujg/HBGPNzXb6tPsKnIcHrAuXHT
    LgJbnS+Hv5UOd+V61yOrl3cPGl9f0i8TwE1N+WBl/WeW463UZPRk4lzXu4qRrs8p
    5Pq4f4vAmiPB/PnH/ewBzPrgKd32FiP9hPKtlvverwWMqkFbD149Wc5xef/BAEQZ
    63ZZkOgRpl0b02onwQ==
    -----END CERTIFICATE-----
    */
    
}