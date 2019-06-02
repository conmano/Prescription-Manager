package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManager;

/**
 * Created by medhas on 5/30/18.
 */

public class KeyManager {
    private static final String sAndroidKeyStore = "AndroidKeyStore";

    public static SecretKey getKey(String keyAlias) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyStore keyStore = KeyStore.getInstance(sAndroidKeyStore);
        keyStore.load(null);

        final KeyStore.Entry keyEntry = keyStore.getEntry(keyAlias, null);

        SecretKey secretKey = null;

        if (keyEntry == null) {
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(false)
                    .setKeySize(128)
                    .build();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    sAndroidKeyStore);

            keyGenerator.init(keyGenParameterSpec);
            secretKey = keyGenerator.generateKey();
        } else {
            secretKey = ((SecretKeyEntry) keyEntry).getSecretKey();
        }

        return secretKey;
    }

    public static SecretKey getKey(String keyAlias,
                                   AuthenticationManager authenticationManager)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyStore keyStore = KeyStore.getInstance(sAndroidKeyStore);
        keyStore.load(null);

        final KeyStore.Entry keyEntry = keyStore.getEntry(keyAlias, null);

        SecretKey secretKey = null;

        if (keyEntry == null) {
            final KeyGenParameterSpec.Builder keyGenParameterSpecBuilder = new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    .setKeySize(128);

            if (authenticationManager.getUserAuthenticationValidityDurationSeconds().isPresent()) {
                keyGenParameterSpecBuilder.setUserAuthenticationValidityDurationSeconds(
                        authenticationManager.getUserAuthenticationValidityDurationSeconds().get());
            }


            final KeyGenParameterSpec keyGenParameterSpec = keyGenParameterSpecBuilder.build();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    sAndroidKeyStore);

            keyGenerator.init(keyGenParameterSpec);
            secretKey = keyGenerator.generateKey();
        } else {
            secretKey = ((SecretKeyEntry) keyEntry).getSecretKey();
        }

        return secretKey;
    }
}
