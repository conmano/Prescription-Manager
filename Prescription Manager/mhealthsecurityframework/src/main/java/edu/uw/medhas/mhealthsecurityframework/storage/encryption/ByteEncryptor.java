package edu.uw.medhas.mhealthsecurityframework.storage.encryption;

import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManager;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.DecryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 5/18/18.
 */

public class ByteEncryptor {
    private static final String sTransformation = "AES/CBC/PKCS7Padding";
    private static final int sIvLength = 16;

    public static void encrypt(String alias, final byte[] plainText,
                               AuthenticationManager authenticationManager,
                               final StorageServiceCallback<byte[]> callback) {
        try {
            final SecretKey secretKey = KeyManager.getKey(alias, authenticationManager);
            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

            authenticationManager.performAuthentication(cryptoObject, new EncryptionServiceCallback() {
                @Override
                public void onWaitingForAuthentication() {
                    callback.onWaitingForAuthentication();
                }

                @Override
                public void onSuccess(Cipher cipher) {
                    try {
                        final byte[] cipherText = cipher.doFinal(plainText);

                        final byte[] ivAndCipherText = new byte[sIvLength + cipherText.length];

                        System.arraycopy(cipher.getIV(), 0, ivAndCipherText, 0, sIvLength);
                        System.arraycopy(cipherText, 0, ivAndCipherText, sIvLength, cipherText.length);

                        callback.onSuccess(ivAndCipherText);
                    } catch (BadPaddingException | IllegalBlockSizeException ex) {
                        Log.e("ByteEncryptor::encrypt",
                                "WebError encrypting data", ex);
                        callback.onFailure(StorageResultErrorType.ENCRYPTION_ERROR);
                    }
                }

                @Override
                public void onFailure(StorageResultErrorType storageResultErrorType) {
                    callback.onFailure(storageResultErrorType);
                }
            });
        } catch (UserNotAuthenticatedException unaex) {
            Log.e("ByteEncryptor::encrypt",
                    "User not authenticated recently", unaex);
            callback.onFailure(StorageResultErrorType.REAUTHENTICATION_NEEDED);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException ex) {
            Log.e("ByteEncryptor::encrypt",
                    "WebError encrypting data", ex);
            callback.onFailure(StorageResultErrorType.ENCRYPTION_ERROR);
        }
    }

    public static void decrypt(String alias, byte[] ivAndCipherText,
                               AuthenticationManager authenticationManager,
                               final StorageServiceCallback<byte[]> callback) {
        try {
            final byte[] iv = new byte[sIvLength];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            final SecretKey secretKey = KeyManager.getKey(alias, authenticationManager);

            final byte[] cipherText = new byte[ivAndCipherText.length - sIvLength];
            System.arraycopy(ivAndCipherText, sIvLength, cipherText, 0, cipherText.length);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

            authenticationManager.performAuthentication(cryptoObject, new EncryptionServiceCallback() {
                @Override
                public void onWaitingForAuthentication() {
                    callback.onWaitingForAuthentication();
                }

                @Override
                public void onSuccess(Cipher cipher) {
                    try {
                        callback.onSuccess(cipher.doFinal(cipherText));
                    } catch (BadPaddingException | IllegalBlockSizeException ex) {
                        Log.e("ByteEncryptor::decrypt",
                                "WebError decrypting data", ex);
                        callback.onFailure(StorageResultErrorType.ENCRYPTION_ERROR);
                    }
                }

                @Override
                public void onFailure(StorageResultErrorType storageResultErrorType) {
                    callback.onFailure(storageResultErrorType);
                }
            });
        } catch (UserNotAuthenticatedException unaex) {
            Log.e("ByteEncryptor::decrypt",
                    "User not authenticated recently", unaex);
            callback.onFailure(StorageResultErrorType.REAUTHENTICATION_NEEDED);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException ex) {
            Log.e("ByteEncryptor::decrypt",
                    "WebError decrypting data", ex);
            callback.onFailure(StorageResultErrorType.DECRYPTION_ERROR);
        }
    }

    public static byte[] encrypt(String alias, byte[] plainText) {
        try {
            final SecretKey secretKey = KeyManager.getKey(alias);
            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            final byte[] cipherText = cipher.doFinal(plainText);
            final byte[] ivAndCipherText = new byte[sIvLength + cipherText.length];

            System.arraycopy(cipher.getIV(), 0, ivAndCipherText, 0, sIvLength);
            System.arraycopy(cipherText, 0, ivAndCipherText, sIvLength, cipherText.length);

            return ivAndCipherText;
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new EncryptionException();
        }
    }

    public static byte[] decrypt(String alias, byte[] ivAndCipherText) {
        try {
            final byte[] iv = new byte[sIvLength];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            final SecretKey secretKey = KeyManager.getKey(alias);

            byte[] cipherText = new byte[ivAndCipherText.length - sIvLength];
            System.arraycopy(ivAndCipherText, sIvLength, cipherText, 0, cipherText.length);

            final Cipher cipher = Cipher.getInstance(sTransformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return cipher.doFinal(cipherText);
        } catch (IOException | CertificateException | UnrecoverableEntryException
                | NoSuchProviderException | KeyStoreException | NoSuchAlgorithmException
                | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
            throw new DecryptionException();
        }
    }
}
