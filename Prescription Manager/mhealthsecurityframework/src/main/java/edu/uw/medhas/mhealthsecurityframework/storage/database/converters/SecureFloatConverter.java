package edu.uw.medhas.mhealthsecurityframework.storage.database.converters;

import android.arch.persistence.room.TypeConverter;
import android.util.Log;

import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;

import edu.uw.medhas.mhealthsecurityframework.authentication.BasicAuthenticationManager;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.ConverterEncryptionResult;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.DecryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.ReauthenticationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhasrivastava on 1/21/19.
 */

public class SecureFloatConverter extends AbstractSecureConverter {
    @TypeConverter
    public byte[] fromSecureFloatToEncryptedBytes(SecureFloat value){
        if (value == null) {
            return null;
        }

        final byte[] objectAsBytes = ByteBuffer.allocate(4).putFloat(value.getValue()).array();

        final ConverterEncryptionResult converterResult = new ConverterEncryptionResult();
        final CountDownLatch latch = new CountDownLatch(1);

        ByteEncryptor.encrypt(getKeyAlias(), objectAsBytes, new BasicAuthenticationManager(),
                new StorageServiceCallback<byte[]>() {
                    @Override
                    public void onSuccess(byte[] result) {
                        converterResult.setResult(result);
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(StorageResultErrorType storageResultErrorType) {
                        converterResult.setErrorType(storageResultErrorType);
                        latch.countDown();
                    }

                    @Override
                    public void onWaitingForAuthentication() {

                    }
                });

        try {
            latch.await();
            if (converterResult.getErrorType().isPresent()) {
                if (StorageResultErrorType.REAUTHENTICATION_NEEDED.equals(converterResult.getErrorType().get())) {
                    throw new ReauthenticationException();
                } else {
                    throw new EncryptionException();
                }
            }
            return converterResult.getResult();
        } catch (InterruptedException e) {
            Log.e("SecureFloatConverter::fromSecureFloatToEncryptedBytes",
                    "Interrupted while encrypting data", e);
            throw new EncryptionException();
        }
    }

    @TypeConverter
    public SecureFloat fromEncryptedBytesToSecureFloat(byte[] encryptedValue) {
        if (encryptedValue == null) {
            return null;
        }

        final ConverterEncryptionResult converterResult = new ConverterEncryptionResult();
        final CountDownLatch latch = new CountDownLatch(1);

        ByteEncryptor.decrypt(getKeyAlias(), encryptedValue, new BasicAuthenticationManager(),
                new StorageServiceCallback<byte[]>() {
                    @Override
                    public void onSuccess(byte[] result) {
                        converterResult.setResult(result);
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(StorageResultErrorType storageResultErrorType) {
                        converterResult.setErrorType(storageResultErrorType);
                        latch.countDown();
                    }

                    @Override
                    public void onWaitingForAuthentication() {
                    }
                });

        try {
            latch.await();
            if (converterResult.getErrorType().isPresent()) {
                if (StorageResultErrorType.REAUTHENTICATION_NEEDED.equals(converterResult.getErrorType().get())) {
                    throw new ReauthenticationException();
                } else {
                    throw new DecryptionException();
                }
            }

            return new SecureFloat(ByteBuffer.wrap(converterResult.getResult()).getFloat());
        } catch (InterruptedException e) {
            Log.e("SecureFloatConverter::fromEncryptedBytesToSecureFloat",
                    "Interrupted while decrypting data", e);
            throw new DecryptionException();
        }
    }
}
