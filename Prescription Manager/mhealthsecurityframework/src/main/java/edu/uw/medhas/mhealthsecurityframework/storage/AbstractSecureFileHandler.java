package edu.uw.medhas.mhealthsecurityframework.storage;

import android.content.Context;
import android.util.Log;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;

import edu.uw.medhas.mhealthsecurityframework.authentication.AuthenticationManagerFactory;
import edu.uw.medhas.mhealthsecurityframework.storage.encryption.ByteEncryptor;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureData;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureFile;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureSerializable;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;

/**
 * Created by medhas on 5/18/18.
 */

public abstract class AbstractSecureFileHandler {
    private final Context mContext;
    private final ObjectMapper mObjectMapper;

    public AbstractSecureFileHandler(Context context) {
        mContext = context;
        mObjectMapper = new ObjectMapper();
    }

    protected Context getContext() {
        return mContext;
    }

    protected ObjectMapper getObjectMapper() {
        return mObjectMapper;
    }

    protected abstract String getKeyAlias();

    protected <S> void getSecureObjAsBytes(StorageWriteObject<S> storageWriteObject,
                                         StorageServiceCallback<byte[]> callback) {
        final byte[] objectAsBytes;

        if (storageWriteObject.getObject() instanceof Serializable) {
            try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
                oos.writeObject(storageWriteObject.getObject());
                oos.flush();
                objectAsBytes = baos.toByteArray();
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                return;
            }
        } else {
            boolean emptyConstructorAvailable = false;
            for (Constructor<?> constructor : storageWriteObject.getObject().getClass().getConstructors()) {
                if (constructor.getParameterCount() == 0) {
                    emptyConstructorAvailable = true;
                }
            }

            if (!emptyConstructorAvailable) {
                callback.onFailure(StorageResultErrorType.DEFAULT_CONSTRUCTOR_ERROR);
                return;
            }

            try {
                objectAsBytes = getObjectMapper().writeValueAsBytes(storageWriteObject.getObject());
                storageWriteObject.getSecureFile().setJsonData(true);
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                return;
            }
        }

        if (storageWriteObject.getObject() instanceof SecureSerializable
                || storageWriteObject.getObject().getClass().isAnnotationPresent(SecureData.class)) {
            storageWriteObject.getSecureFile().setEncryptedData(true);
            ByteEncryptor.encrypt(getKeyAlias(), objectAsBytes,
                    AuthenticationManagerFactory.getAuthenticationManager(), callback);
            return;
        }

        callback.onSuccess(objectAsBytes);
    }

    protected <S> void readObjFromBytes(final StorageReadObject<S> storageReadObject,
                                        final StorageServiceCallback<S> callback) {
        if (storageReadObject.getSecureFile().isEncryptedData()) {
            ByteEncryptor.decrypt(getKeyAlias(), storageReadObject.getObjectBytes(),
                    AuthenticationManagerFactory.getAuthenticationManager(),
                    new StorageServiceCallback<byte[]>() {
                        @Override
                        public void onWaitingForAuthentication() {
                            callback.onWaitingForAuthentication();
                        }

                        @Override
                        public void onSuccess(byte[] result) {
                            if (storageReadObject.getSecureFile().isJsonData()) {
                                try {
                                    callback.onSuccess(getObjectMapper().readValue(result,
                                            storageReadObject.getClazz()));
                                } catch (IOException ioex) {
                                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                                            "WebError deserializing object", ioex);
                                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                                }
                            } else {
                                try (final ByteArrayInputStream bais = new ByteArrayInputStream(result);
                                     final ObjectInputStream ois = new ObjectInputStream(bais);) {
                                    callback.onSuccess((S) ois.readObject());
                                } catch (IOException | ClassNotFoundException ex) {
                                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                                            "WebError deserializing object", ex);
                                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                                }
                            }
                        }

                        @Override
                        public void onFailure(StorageResultErrorType storageResultErrorType) {
                            callback.onFailure(storageResultErrorType);
                        }
                    });
        } else {
            if (storageReadObject.getSecureFile().isJsonData()) {
                try {
                    callback.onSuccess(getObjectMapper().readValue(storageReadObject.getObjectBytes(),
                            storageReadObject.getClazz()));
                } catch (IOException ioex) {
                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                            "WebError deserializing object", ioex);
                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                }
            } else {
                try (final ByteArrayInputStream bais = new ByteArrayInputStream(
                        storageReadObject.getObjectBytes());
                     final ObjectInputStream ois = new ObjectInputStream(bais);) {
                    callback.onSuccess((S) ois.readObject());
                } catch (IOException | ClassNotFoundException ex) {
                    Log.e("AbstractSecureFileHandler::readObjFromBytes",
                            "WebError deserializing object", ex);
                    callback.onFailure(StorageResultErrorType.SERIALIZATION_ERROR);
                }
            }
        }
    }

    protected <S> byte[] getSecureObjAsBytes(S secureObj, SecureFile secureFile) {
        final byte[] objectAsBytes;

        if (secureObj instanceof Serializable) {
            try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
                oos.writeObject(secureObj);
                oos.flush();
                objectAsBytes = baos.toByteArray();
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                throw new SerializationException();
            }
        } else {
            boolean emptyConstructorAvailable = false;
            for (Constructor<?> constructor : secureObj.getClass().getConstructors()) {
                if (constructor.getParameterCount() == 0) {
                    emptyConstructorAvailable = true;
                }
            }

            if (!emptyConstructorAvailable) {
                throw new NoDefaultConstructorException();
            }

            try {
                objectAsBytes = mObjectMapper.writeValueAsBytes(secureObj);
                secureFile.setJsonData(true);
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError serializing object", ioex);
                throw new SerializationException();
            }
        }

        if (secureObj instanceof SecureSerializable
                || secureObj.getClass().isAnnotationPresent(SecureData.class)) {
            secureFile.setEncryptedData(true);
            return ByteEncryptor.encrypt(getKeyAlias(), objectAsBytes);
        }

        return objectAsBytes;
    }

    protected <S> S readObjFromBytes(Class<S> clazz, byte[] secureObjectAsBytes, SecureFile secureFile) {
        final byte[] unsecureObjectAsBytes = secureFile.isEncryptedData()
                                                ? ByteEncryptor.decrypt(getKeyAlias(), secureObjectAsBytes)
                                                : secureObjectAsBytes;

        if (secureFile.isJsonData()) {
            try {
                return mObjectMapper.readValue(unsecureObjectAsBytes, clazz);
            } catch (IOException ioex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError deserializing object", ioex);
                throw new SerializationException();
            }
        } else {
            try (final ByteArrayInputStream bais = new ByteArrayInputStream(unsecureObjectAsBytes);
                 final ObjectInputStream ois = new ObjectInputStream(bais);) {
                return (S) ois.readObject();
            } catch (IOException | ClassNotFoundException ex) {
                Log.e("AbstractSecureFileHandler::getSecureObjAsBytes",
                        "WebError deserializing object", ex);
                throw new SerializationException();
            }
        }
    }
}
