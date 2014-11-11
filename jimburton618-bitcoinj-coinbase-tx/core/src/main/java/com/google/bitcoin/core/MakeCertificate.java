/*
 * Copyright 2011 gitblit.com.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.bitcoin.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utility class to generate self-signed certificates.
 * 
 * @author James Moger
 * 
 */
public class MakeCertificate {

        private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

        public static void generateSelfSignedCertificate(String hostname, File keystore,
                        String keystorePassword) {
                try {
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

                        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
                        kpGen.initialize(1024, new SecureRandom());
                        KeyPair pair = kpGen.generateKeyPair();

                        // Generate self-signed certificate
                        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
                        builder.addRDN(BCStyle.CN, hostname);

                        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
                        Date notAfter = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);
                        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

                        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(),
                                        serial, notBefore, notAfter, builder.build(), pair.getPublic());
                        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                                        .setProvider(BC).build(pair.getPrivate());
                        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC)
                                        .getCertificate(certGen.build(sigGen));
                        cert.checkValidity(new Date());
                        cert.verify(cert.getPublicKey());

                        // Save to keystore
                        KeyStore store = KeyStore.getInstance("BKS");
                        if (keystore.exists()) {
                                FileInputStream fis = new FileInputStream(keystore);
                                store.load(fis, keystorePassword.toCharArray());
                                fis.close();
                        } else {
                                store.load(null);
                        }
                        store.setKeyEntry(hostname, pair.getPrivate(), keystorePassword.toCharArray(),
                                        new java.security.cert.Certificate[] { cert });
                        FileOutputStream fos = new FileOutputStream(keystore);
                        store.store(fos, keystorePassword.toCharArray());
                        fos.close();
                } catch (Throwable t) {
                        t.printStackTrace();
                        throw new RuntimeException("Failed to generate self-signed certificate!", t);
                }
        }

        public static void generateSelfSignedCertificate(String hostname, File keystore,
                        String keystorePassword, String info) {
                try {
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

                        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
                        kpGen.initialize(1024, new SecureRandom());
                        KeyPair pair = kpGen.generateKeyPair();

                        // Generate self-signed certificate
                        X500Principal principal = new X500Principal(info);

                        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
                        Date notAfter = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);
                        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

                        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(principal, serial,
                                        notBefore, notAfter, principal, pair.getPublic());
                        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                                        .setProvider(BC).build(pair.getPrivate());
                        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC)
                                        .getCertificate(certGen.build(sigGen));
                        cert.checkValidity(new Date());
                        cert.verify(cert.getPublicKey());

                        // Save to keystore
                        KeyStore store = KeyStore.getInstance("BKS");
                        if (keystore.exists()) {
                                FileInputStream fis = new FileInputStream(keystore);
                                store.load(fis, keystorePassword.toCharArray());
                                fis.close();
                        } else {
                                store.load(null);
                        }
                        store.setKeyEntry(hostname, pair.getPrivate(), keystorePassword.toCharArray(),
                                        new java.security.cert.Certificate[] { cert });
                        FileOutputStream fos = new FileOutputStream(keystore);
                        store.store(fos, keystorePassword.toCharArray());
                        fos.close();
                } catch (Throwable t) {
                        t.printStackTrace();
                        throw new RuntimeException("Failed to generate self-signed certificate!", t);
                }
        }
        
        public static void addPublicCert(String alias, X509Certificate cert, File keystore, String keystorePassword) {
	        try {
	            // Save to keystore
	            KeyStore store = KeyStore.getInstance("BKS");
	            if (keystore.exists()) {
	                    FileInputStream fis = new FileInputStream(keystore);
	                    store.load(fis, keystorePassword.toCharArray());
	                    fis.close();
	            } else {
	                    store.load(null);
	            }
	            
	            store.setCertificateEntry(alias, cert);
	            FileOutputStream fos = new FileOutputStream(keystore);
	            store.store(fos, keystorePassword.toCharArray());
	            fos.close();
	        } catch (Throwable t) {
	        	t.printStackTrace();
	        	throw new RuntimeException("Failed to generate self-signed certificate!", t);
	        }
        }
}