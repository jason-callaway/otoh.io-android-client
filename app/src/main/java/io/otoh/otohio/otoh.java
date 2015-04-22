package io.otoh.otohio;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
//import java.security.cert.X509Extension;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.util.Vector;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.cms.Attributes;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.Attribute;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.asn1.x509.X509Name;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.bcpg.sig.Features;
import org.spongycastle.bcpg.sig.KeyFlags;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.CMSTypedData;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.PKCS10CertificationRequest;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
//import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.util.Store;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.jce.spec.ECParameterSpec;

/**
 * Created by jason on 8/20/14.
 */
public class otoh {
    public static final String APIURL = "https://api.otoh.io/";
    public static final String APIVERSION = "0.1";

    private SSLContext sslContext;
    private TrustManagerFactory tmf;

    public String postWithJSON(JSONObject json, URL url) throws Exception {
        String output = null;
        try {
//			JSONObject j = new JSONObject(json);
            byte[] bytes = json.toString().getBytes();

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            //new
            conn.setSSLSocketFactory(sslContext.getSocketFactory());

            conn.setRequestMethod("POST");
            conn.addRequestProperty("Content-Length", "" + bytes.length);
            conn.addRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setDoInput(true);

            OutputStream out = (OutputStream) conn.getOutputStream();
            out.write(bytes);
            out.flush();
            out.close();

            //int responseCode = conn.getResponseCode();
            BufferedReader read = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line = "";
            while((line = read.readLine()) != null) {
                response.append(line);
            }
            output = response.toString();

        } catch (Exception e) {
            throw e;
        }

        return output;
    } // end postWithJSON

    public String putWithJSON(JSONObject json, URL url) throws Exception {
        String output = null;
        try {
//			JSONObject j = new JSONObject(json);
            byte[] bytes = json.toString().getBytes();

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

            conn.setSSLSocketFactory(sslContext.getSocketFactory());

            conn.setRequestMethod("PUT");
            conn.addRequestProperty("Content-Length", "" + bytes.length);
            conn.addRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setDoInput(true);

            OutputStream out = (OutputStream) conn.getOutputStream();
            out.write(bytes);
            out.flush();
            out.close();

            //int responseCode = conn.getResponseCode();
            BufferedReader read = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line = "";
            while((line = read.readLine()) != null) {
                response.append(line);
            }
            output = response.toString();

        } catch (Exception e) {
            throw e;
        }

        return output;
    } // end postWithJSON

    public String postWithJSONCert(KeyStore k, String kp, JSONObject json, URL url) throws Exception {
        String output = null;
        try {
            byte[] bytes = json.toString().getBytes();

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

//            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(k, kp.toCharArray());
            SSLContext context = SSLContext.getInstance("TLSv1.1");
//          context.init(kmf.getKeyManagers(), null, new SecureRandom());
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            SSLSocketFactory sockFact = context.getSocketFactory();
            conn.setSSLSocketFactory( sockFact );

            conn.setRequestMethod("POST");
            conn.addRequestProperty("Content-Length", "" + bytes.length);
            conn.addRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setDoInput(true);

            OutputStream out = (OutputStream) conn.getOutputStream();
            out.write(bytes);
            out.flush();
            out.close();

            //int responseCode = conn.getResponseCode();
            BufferedReader read = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line = "";
            while((line = read.readLine()) != null) {
                response.append(line);
            }
            output = response.toString();

        } catch (Exception e) {
            throw e;
        }

        return output;
    } // end postWithJSONCert

    public String getWithCert(KeyStore k, String kp, URL url) throws Exception {
        String output = null;
        try {
//			byte[] bytes = json.toString().getBytes();

            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

//            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(k, kp.toCharArray());
            SSLContext context = SSLContext.getInstance("TLSv1.2");
//            context.init(kmf.getKeyManagers(), null, new SecureRandom());
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            SSLSocketFactory sockFact = context.getSocketFactory();
            conn.setSSLSocketFactory( sockFact );

            conn.setRequestMethod("GET");
//			conn.addRequestProperty("Content-Length", "" + bytes.length);
//			conn.addRequestProperty("Content-Type", "application/json");
//			conn.setDoOutput(true);
            conn.setDoInput(true);

//			OutputStream out = (OutputStream) conn.getOutputStream();
//			out.write(bytes);
//			out.flush();
//			out.close();

            //int responseCode = conn.getResponseCode();
            BufferedReader read = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line = "";
            while((line = read.readLine()) != null) {
                response.append(line);
            }
            output = response.toString();

        } catch (Exception e) {
            throw e;
        }

        return output;
    } // end postWithJSONCert

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "SC");
        //kpGen.initialize(4096, new SecureRandom());
        kpGen.initialize(512, new SecureRandom());
        return kpGen.generateKeyPair();
    }

    public static Vector generatePGPKeyPair(String nickname, String email, String password) throws Exception {
        String identity = nickname + " <" + email + ">";
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

        /*
         *  The first argument to RSAKeyGenerationParameters is the RSA public exponent, which needs
         *  to be a Fermat Number, specifically a Fermat prime.  There are only a few known Fermat
         *  primes: 3, 5, 17, 257, 65537.  Most people use 65537, although 3 should also be safe.
         *  In my experimentation, using 3 is not perceptibly faster, so we're using 65537 which is
         *  0x10001.
         *  Reference:
         *    * http://goo.gl/iTPctB (BouncyCastle docs)
         *    * http://goo.gl/JmDl7t (Crypto StackExchange)
         *    * http://en.wikipedia.org/wiki/Fermat_number
         *    * http://oeis.org/A000215
         */
        // TODO: Make key length a passable parameter
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 512, 12));

        PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
        PGPKeyPair rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();
        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER);
        signhashgen.setPreferredSymmetricAlgorithms(false, new int[] {SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128});
        signhashgen.setPreferredHashAlgorithms(false, new int[] {HashAlgorithmTags.SHA1, HashAlgorithmTags.SHA224, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512});
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, 0xff)).build(password.toCharArray());

        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign, identity, sha1Calc, signhashgen.generate(), null, new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256), pske);

        keyRingGenerator.addSubKey(rsakp_enc, enchashgen.generate(), null);

        PGPPublicKeyRing pkr = keyRingGenerator.generatePublicKeyRing();
        PGPSecretKeyRing skr = keyRingGenerator.generateSecretKeyRing();

        Vector v = new Vector();
        v.addElement(pkr);
        v.addElement(skr);
        return v;
    }

    @SuppressWarnings("deprecation")
    public static String generateCSR(KeyPair pair, String username, String email, String keyUse, String fingerprint) throws Exception {

        GeneralName emailGN = new GeneralName(GeneralName.rfc822Name, email);
        DERSequence othernameSequence =
                new DERSequence(new ASN1Encodable[] {
                        new DERObjectIdentifier("1.2.3.4"),
                        new DERTaggedObject(true, 0, new DERUTF8String(fingerprint))
                });
        GeneralName othernameGN = new GeneralName(GeneralName.otherName, othernameSequence);
        //GeneralNames subjectAltNames = new GeneralNames(new DERSequence(new ASN1Encodable[] {emailGN, othernameGN}));
        GeneralNames subjectAltNames = new GeneralNames(new GeneralName[] {emailGN, othernameGN});

        Vector oids = new Vector();
        Vector values = new Vector();
        oids.add(X509Extensions.SubjectAlternativeName);
        values.add(new X509Extension(false, new DEROctetString(subjectAltNames)));
        X509Extensions extensions = new X509Extensions(oids, values);
        Attribute attributes = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest("SHA256withRSA",
                                                                        new X500Principal("C=US,ST=Maryland,L=Frederick,O=Catoctin Systems LLC,OU=otoh,CN=" + username + "-" + keyUse),
                                                                        pair.getPublic(),
                                                                        new DERSet(attributes),
                                                                        pair.getPrivate());

        String s = new String(Base64.encode(csr.getEncoded()));
        String csrString = s.replaceAll("(.{65})", "$1\n");
        csrString = "-----BEGIN CERTIFICATE REQUEST-----\n" + csrString + "\n-----END CERTIFICATE REQUEST-----";
        return csrString;
    }

    public JSONObject createCertificate(KeyStore k, String kp, String u, String csr, String ak, String in) throws Exception {
        String urlString = APIURL + APIVERSION + "/certificates/" + u;
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        JSONObject j = new JSONObject();
        j.put("csr", csr.replaceAll("\n", "\\\n"));
        j.put("key_use", "ke");
        j.put("username", u);
        j.put("identity_name", in);

        String output = null;
        try {
            System.out.println("PUT " + urlString + " - " + j.toString());
            output = postWithJSONCert(k, kp, j, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONObject(output);
    }

    public JSONObject createUserCertificate(String u, String csr, String ak, String in) throws Exception {
        String urlString = APIURL + APIVERSION + "/newuser/" + u;
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        JSONObject j = new JSONObject();
        j.put("csr", csr.replaceAll("\n", "\\\n"));
        j.put("key_use", "ds");
        j.put("access_key", ak);
        j.put("username", u);
        j.put("identity_name", in);

        String output = null;
        try {
            System.out.println("PUT " + urlString + " - " + j.toString());
            output = putWithJSON(j, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONObject(output);
    }

    public JSONObject handleReputation(String action, String vouching_cn,
                                       String target_cn, KeyStore keystore,
                                       X509Certificate target,	String keystorePassword,
                                       String keystorePath, String latitude, String longitude,
                                       String altitude) throws Exception {
//		String urlString = APIURL + APIVERSION + "/reputation/" + action;
        String urlString = APIURL + APIVERSION + "/reputation";
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        // grab the target ds cert
        char[] p = keystorePassword.toCharArray();
        FileInputStream fin = new FileInputStream(keystorePath);
        keystore.load(fin, p);
        fin.close();
        X509Certificate myx509cert = (X509Certificate) keystore.getCertificate("dscert");
        char[] passwordChar = keystorePassword.toCharArray();
        Key myPrivKey = keystore.getKey("dskey", passwordChar);

        // fire up BC CMS stuff
        CMSTypedData msg = new CMSProcessableByteArray(target.toString().getBytes());
        List cmsCertList = new ArrayList();
        cmsCertList.add(myx509cert);
        Store cmsCerts = new JcaCertStore(cmsCertList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("SC").build((PrivateKey)myPrivKey);

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("SC").build())
                        .build(sha256Signer, myx509cert));

        gen.addCertificates(cmsCerts);

        CMSSignedData sigData = gen.generate(msg, false);

        String signature = new String(Base64.encode(sigData.getEncoded()));

        // build our JSON object
        // TODO: flesh this out with new logic
        JSONObject j = new JSONObject();
        j.put("vouch", action);
        j.put("vouching_cn", vouching_cn);
        j.put("target_cn", target_cn);
//		j.put("vouching_cert_sn", myx509cert.getSerialNumber().toString());
//		j.put("target_cert_sn", target.getSerialNumber().toString());
        j.put("signature", signature);
        if (latitude != null) {
            j.put("latitude", latitude);
        }
        if (longitude != null) {
            j.put("longitude", longitude);
        }
        if (altitude != null) {
            j.put("altitude", altitude);
        }

        String output = null;
        try {
            System.out.println("POST " + urlString + " - " + j.toString());
            output = postWithJSONCert(keystore, keystorePassword, j, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONObject("{'result': 'success'}");

    }

    public JSONObject createReputation(String vouching_cn, String target_cn,
                                       KeyStore keystore, X509Certificate target,
                                       String keystorePassword, String keystorePath, String latitude,
                                       String longitude, String altitude) throws Exception {
        return handleReputation("vouch", vouching_cn, target_cn, keystore, target,
                keystorePassword, keystorePath, latitude, longitude, altitude);
    }

    public JSONObject burnReputation(String vouching_cn, String target_cn,
                                     KeyStore keystore, X509Certificate target,
                                     String keystorePassword, String keystorePath, String latitude,
                                     String longitude, String altitude) throws Exception {
        return handleReputation("burn", vouching_cn, target_cn, keystore, target,
                keystorePassword, keystorePath, latitude, longitude, altitude);
    }

    public JSONObject createUser(String u) throws Exception {
        String urlString = new String(APIURL + APIVERSION + "/newuser");
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        JSONObject j = new JSONObject();
        j.put("action", "create");
        j.put("username", u);

        String output = null;
        try {
            // debug
            System.out.println("POST " + urlString + " - " + j.toString());
            output = postWithJSON(j, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONObject(output);
    }

    public JSONObject readUser(KeyStore keystore, String keystorePassword, String u) throws Exception {
        String urlString = new String(APIURL + APIVERSION + "/users/" + u);
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        String output = null;
        try {
            System.out.println("GET " + urlString);
            output = getWithCert(keystore, keystorePassword, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONObject(output);
    }

    public JSONObject readCertById(KeyStore keystore, String keystorePassword, String id) throws Exception {
        String urlString = new String(APIURL + APIVERSION + "/certificates/" + id);
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        String output = null;
        try {
            System.out.println("GET " + urlString);
            output = getWithCert(keystore, keystorePassword, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONObject(output);
    }

    public JSONArray readCertsByUsername(KeyStore keystore, String keystorePassword,
                                         String username, String keyUse) throws Exception {
        String urlString = new String(APIURL + APIVERSION + "/certificates/" +
                username + "?key_use=" + keyUse + "&search_by=username");
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        String output = null;
        try {
            System.out.println("GET " + urlString);
            output = getWithCert(keystore, keystorePassword, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONArray(output);
    }

    public JSONArray readCertsByIdentity(KeyStore keystore, String keystorePassword,
                                         String identity, String keyUse) throws Exception {
        String urlString = new String(APIURL + APIVERSION + "/certificates/" +
                identity + "?key_use=" + keyUse + "&search_by=identity");
        urlString = urlString.replaceAll(" ", "%20");
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new Exception(e);
        }

        String output = null;
        try {
            System.out.println("GET " + urlString);
            output = getWithCert(keystore, keystorePassword, url);
        } catch (Exception e) {
            throw e;
        }

        return new JSONArray(output);
    }

    public otoh(String ca) {
        // TODO Auto-generated constructor stub

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate caCert = cf.generateCertificate((InputStream) new ByteArrayInputStream(ca.getBytes()));
            String keyStoreType = KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", caCert);
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            this.tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);
            this.sslContext = SSLContext.getInstance("TLSv1.2");
            this.sslContext.init(null, tmf.getTrustManagers(), null);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
