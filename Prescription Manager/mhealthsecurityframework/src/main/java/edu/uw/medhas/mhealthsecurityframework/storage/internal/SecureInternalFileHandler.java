package edu.uw.medhas.mhealthsecurityframework.storage.internal;

import android.content.Context;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.uw.medhas.mhealthsecurityframework.storage.AbstractSecureFileHandler;
import edu.uw.medhas.mhealthsecurityframework.storage.StorageServiceCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.EncryptionException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;

/**
 * Created by medhas on 5/18/18.
 */

public class SecureInternalFileHandler extends AbstractSecureFileHandler {
    public SecureInternalFileHandler(Context context) {
        super(context);
    }

    @Override
    protected String getKeyAlias() {
        return "mhealth-security-framework-internal-storage";
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
                try (final FileOutputStream fos = getContext().openFileOutput(
                        storageWriteObject.getSecureFile().getFinalFilename(), Context.MODE_PRIVATE)) {
                    fos.write(result);
                    storageResultCallback.onSuccess(new StorageResult<>(new StorageResultSuccess()));
                } catch (IOException ioex) {
                    Log.e("SecureInternalFileHandler::writeData",
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
        if (fileExists(storageReadObject.getSecureFile().getJsonEncryptedFileName())) {
            storageReadObject.getSecureFile().setJsonData(true);
            storageReadObject.getSecureFile().setEncryptedData(true);
        } else if (fileExists(storageReadObject.getSecureFile().getJsonFileName())) {
            storageReadObject.getSecureFile().setJsonData(true);
        } else if (fileExists(storageReadObject.getSecureFile().getEncryptedFileName())) {
            storageReadObject.getSecureFile().setEncryptedData(true);
        }

        final String finalFileName = storageReadObject.getSecureFile().getFinalFilename();
        byte[] objectAsBytes = new byte[(int) getContext().getFileStreamPath(finalFileName).length()];

        try (final FileInputStream fis = getContext().openFileInput(finalFileName)) {
            fis.read(objectAsBytes);
        } catch (FileNotFoundException fnfex) {
            Log.e("SecureInternalFileHandler::readData",
                    "File " + finalFileName + " not found", fnfex);
            storageResultCallback.onFailure(StorageResultErrorType.FILE_NOT_FOUND_ERROR);
            return;
        } catch (IOException ioex) {
            Log.e("SecureInternalFileHandler::readData",
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

        try (final FileOutputStream fos = getContext().openFileOutput(secureFile.getFinalFilename(),
                Context.MODE_PRIVATE)) {
            fos.write(secureObjectAsBytes);
        } catch (IOException ioex) {
            ioex.printStackTrace();
            throw new SerializationException();
        }
    }

    public <S> S readData(Class<S> clazz, String filename) throws FileNotFoundException {
        final SecureFile secureFile = new SecureFile(filename);

        if (fileExists(secureFile.getJsonEncryptedFileName())) {
            secureFile.setJsonData(true);
            secureFile.setEncryptedData(true);
        } else if (fileExists(secureFile.getJsonFileName())) {
            secureFile.setJsonData(true);
        } else if (fileExists(secureFile.getEncryptedFileName())) {
            secureFile.setEncryptedData(true);
        }

        final String finalFileName = secureFile.getFinalFilename();
        byte[] objectAsBytes = new byte[(int) getContext().getFileStreamPath(finalFileName).length()];

        try (final FileInputStream fis = getContext().openFileInput(finalFileName)) {
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

    private boolean fileExists(String filename) {
        return getContext().getFileStreamPath(filename).exists();
    }
}
