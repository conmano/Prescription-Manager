package edu.uw.medhas.mhealthsecurityframework.storage.cache;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;

/**
 * Created by medhas on 10/18/18.
 */

public class SecureCacheHandler extends AbstractSecureFileHandler {
    public SecureCacheHandler(Context context) {
        super(context);
    }

    @Override
    protected String getKeyAlias() {
        return "mhealth-security-framework-cache-storage";
    }

    public <S> void writeData(final StorageWriteObject<S> storageWriteObject,
                              final StorageResultCallback<StorageResultSuccess> storageResultCallback) {
        getSecureObjAsBytes(storageWriteObject, new StorageServiceCallback<byte[]>() {
            @Override
            public void onWaitingForAuthentication() {
                storageResultCallback.onWaitingForAuthentication();
            }

            @Override
            public void onSuccess(byte[] result) {
                final File finalFileName = getFile(storageWriteObject.getSecureFile().getFinalFilename());

                try (final FileOutputStream fos = new FileOutputStream(finalFileName)) {
                    fos.write(result);
                    storageResultCallback.onSuccess(new StorageResult<>(new StorageResultSuccess()));
                } catch (IOException ioex) {
                    Log.e("SecureCacheHandler::writeData",
                            "WebError serializing object", ioex);
                    storageResultCallback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                }
            }

            @Override
            public void onFailure(StorageResultErrorType storageResultErrorType) {
                storageResultCallback.onFailure(storageResultErrorType);
            }
        });
    }

    public <S> void readData(final StorageReadObject<S> storageReadObject,
                             final StorageResultCallback<S> storageResultCallback) {
        if (getFile(storageReadObject.getSecureFile().getJsonEncryptedFileName()).exists()) {
            storageReadObject.getSecureFile().setJsonData(true);
            storageReadObject.getSecureFile().setEncryptedData(true);
        } else if (getFile(storageReadObject.getSecureFile().getJsonFileName()).exists()) {
            storageReadObject.getSecureFile().setJsonData(true);
        } else if (getFile(storageReadObject.getSecureFile().getEncryptedFileName()).exists()) {
            storageReadObject.getSecureFile().setEncryptedData(true);
        }

        final File finalFileName = getFile(storageReadObject.getSecureFile().getFinalFilename());
        byte[] objectAsBytes = new byte[(int) finalFileName.length()];

        try (final FileInputStream fis = new FileInputStream(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            Log.e("SecureCacheHandler::readData",
                    "File " + finalFileName.getName() + " not found", fnfex);
            storageResultCallback.onFailure(StorageResultErrorType.FILE_NOT_FOUND_ERROR);
            return;
        } catch (IOException ioex) {
            Log.e("SecureCacheHandler::readData",
                    "WebError deserializing object", ioex);
            storageResultCallback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
            return;
        }

        storageReadObject.setObjectBytes(objectAsBytes);

        readObjFromBytes(storageReadObject, new StorageServiceCallback<S>() {
            @Override
            public void onWaitingForAuthentication() {
                storageResultCallback.onWaitingForAuthentication();
            }

            @Override
            public void onSuccess(S result) {
                storageResultCallback.onSuccess(new StorageResult<>(result));
            }

            @Override
            public void onFailure(StorageResultErrorType storageResultErrorType) {
                storageResultCallback.onFailure(storageResultErrorType);
            }
        });
    }

    public <S> void writeData(S secureObj, String filename) {
        final SecureFile secureFile = new SecureFile(filename);

        final byte[] secureObjectAsBytes = getSecureObjAsBytes(secureObj, secureFile);

        final File finalFileName = getFile(secureFile.getFinalFilename());

        try (final FileOutputStream fos = new FileOutputStream(finalFileName)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) throws FileNotFoundException {
        final SecureFile secureFile = new SecureFile(filename);

        if (getFile(secureFile.getJsonEncryptedFileName()).exists()) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (getFile(secureFile.getJsonFileName()).exists()) {
            secureFile.setJsonData(true);
        } else if (getFile(secureFile.getEncryptedFileName()).exists()) {
            secureFile.setEncryptedData(true);
        }

        final File finalFileName = getFile(secureFile.getFinalFilename());
        byte[] objectAsBytes = new byte[(int) finalFileName.length()];

        try (final FileInputStream fis = new FileInputStream(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            fnfex.printStackTrace();
            throw fnfex;
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }

        return readObjFromBytes(clazz, objectAsBytes, secureFile);
    }

    private File getFile(String filename) {
        return new File(getContext().getCacheDir(), filename);
    }
}
