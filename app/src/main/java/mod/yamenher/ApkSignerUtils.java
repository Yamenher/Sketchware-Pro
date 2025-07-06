package mod.yamenher;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkSigner.SignerConfig;
import com.android.apksig.util.DataSources;

import java.io.*;
import java.nio.channels.FileChannel;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

import android.sun.security.provider.JavaKeyStoreProvider;

import mod.jbk.build.BuiltInLibraries;

import pro.sketchware.SketchApplication;

public class ApkSignerUtils {

    private static final String TestkeyFolder = BuiltInLibraries.EXTRACTED_COMPILE_ASSETS_PATH.getAbsolutePath() + "/testkey/";

    public interface SignCallback {
        void onSuccess(File signedApk);
        void onFailure(Exception e);
    }

    public static void signFileWithReleaseKey(String inputFile, String outputFile, String keyFile, String keyAlias, String keystorePassword, String keyPassword, SignCallback callback) {
        new Thread(() -> {
            File errorLogFile = new File("/storage/emulated/0/sketchware/logs/SigningError.txt");

            try {
                KeyStore keyStore = KeyStore.getInstance("JKS", new JavaKeyStoreProvider());
                try (FileInputStream fis = new FileInputStream(new File(keyFile))) {
                    keyStore.load(fis, keystorePassword.toCharArray());
                }

                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
                Certificate[] certChain = keyStore.getCertificateChain(keyAlias);
                if (certChain == null || certChain.length == 0) throw new Exception("Certificate chain is empty.");

                List<X509Certificate> certificateList = new ArrayList<>();
                for (Certificate cert : certChain) {
                    if (cert instanceof X509Certificate) certificateList.add((X509Certificate) cert);
                }

                if (certificateList.isEmpty()) throw new Exception("No valid X509Certificate found.");

                SignerConfig signerConfig = new SignerConfig.Builder(keyAlias, privateKey, certificateList).build();

                try (FileChannel inputChannel = new FileInputStream(new File(inputFile)).getChannel()) {
                    ApkSigner.Builder builder = new ApkSigner.Builder(Collections.singletonList(signerConfig));
                    builder.setInputApk(DataSources.asDataSource(inputChannel));
                    builder.setOutputApk(new File(outputFile));
                    builder.setV1SigningEnabled(true);
                    builder.setV2SigningEnabled(true);
                    builder.setV3SigningEnabled(true);
                    builder.setV4SigningEnabled(true);
                    builder.setV4SignatureOutputFile(new File(outputFile + ".idsig"));
                    builder.build().sign();
                }

                if (callback != null) callback.onSuccess(new File(outputFile));

            } catch (Exception e) {
                logError(errorLogFile, e);
                if (callback != null) callback.onFailure(e);
            }
        }).start();
    }

    public static void signWithTestkey(String inputApk, String outputApk, SignCallback callback) {
        new Thread(() -> {
            File inputFile = new File(inputApk);
            File pemFile = new File(TestkeyFolder + "/testkey.x509.pem");
            File pk8File = new File(TestkeyFolder + "/testkey.pk8");
            File outputFile = new File(outputApk);

            try {
                List<X509Certificate> certs = loadCertificates(pemFile);
                PrivateKey privateKey = loadPrivateKey(pk8File);
                SignerConfig signerConfig = new SignerConfig.Builder("testkey", privateKey, certs).build();

                ApkSigner.Builder builder = new ApkSigner.Builder(Collections.singletonList(signerConfig));
                builder.setInputApk(inputFile);
                builder.setOutputApk(outputFile);
                builder.setV1SigningEnabled(true);
                builder.setV2SigningEnabled(true);
                builder.setV3SigningEnabled(true);
                builder.setV4SigningEnabled(true);
                builder.setV4SignatureOutputFile(new File(outputApk.replace(".apk", ".idsig")));
                builder.setAlignFileSize(true);
                builder.build().sign();

                if (callback != null) callback.onSuccess(outputFile);

            } catch (Exception e) {
                logError(new File("/sdcard/sketchware/logs/SigningError.txt"), e);
                if (callback != null) callback.onFailure(e);
            }
        }).start();
    }

    private static PrivateKey loadPrivateKey(File pk8File) throws Exception {
        try (FileInputStream fis = new FileInputStream(pk8File)) {
            byte[] keyBytes = readAllBytes(fis);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        }
    }

    private static List<X509Certificate> loadCertificates(File pemFile) throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        try (BufferedReader reader = new BufferedReader(new FileReader(pemFile))) {
            StringBuilder certContent = new StringBuilder();
            String line;
            boolean inCert = false;

            while ((line = reader.readLine()) != null) {
                if (line.contains("BEGIN CERTIFICATE")) {
                    inCert = true;
                    certContent.setLength(0);
                } else if (line.contains("END CERTIFICATE")) {
                    inCert = false;
                    byte[] certBytes = Base64.getDecoder().decode(certContent.toString());
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
                    certs.add(cert);
                } else if (inCert) {
                    certContent.append(line.trim());
                }
            }
        }

        return certs;
    }

    private static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] temp = new byte[4096];
        int read;
        while ((read = is.read(temp)) != -1) {
            buffer.write(temp, 0, read);
        }
        return buffer.toByteArray();
    }

    private static void logError(File logFile, Exception e) {
        try (FileOutputStream fos = new FileOutputStream(logFile, true);
             PrintWriter writer = new PrintWriter(fos)) {
            writer.println("Exception: " + e.toString());
            e.printStackTrace(writer);
        } catch (Exception logEx) {
            logEx.printStackTrace();
        }
    }
}