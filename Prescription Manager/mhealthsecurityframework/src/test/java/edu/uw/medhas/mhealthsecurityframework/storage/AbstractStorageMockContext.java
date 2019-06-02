package edu.uw.medhas.mhealthsecurityframework.storage;

import android.test.mock.MockContext;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.UUID;

import edu.uw.medhas.mhealthsecurityframework.storage.constants.StorageConstants;

/**
 * Created by medhas on 11/3/18.
 */

public abstract class AbstractStorageMockContext extends MockContext implements AutoCloseable {
    private final TemporaryFolder tempFolder;

    private String fileName;
    private File fileThatExists;

    private final SecureTestData secureData;
    private final SecureTestSerializable secureSerializable;
    private final TestData testData;
    private final TestSerializableData testSerializableData;

    private final BadSecureTestData badSecureTestData;

    private final String data = UUID.randomUUID().toString();

    private FileInputStream fis;

    public AbstractStorageMockContext(TemporaryFolder tempFolder) {
        this.tempFolder = tempFolder;

        secureData = new SecureTestData();
        secureData.setData(data);

        secureSerializable = new SecureTestSerializable();
        secureSerializable.setData(data);

        testData = new TestData();
        testData.setData(data);

        testSerializableData = new TestSerializableData();
        testSerializableData.setData(data);

        badSecureTestData = new BadSecureTestData(data);
    }

    protected String constructFileName(String fileName, boolean isJson, boolean isEncryped) {
        if (isJson) {
            fileName = fileName + StorageConstants.sJsonExtension;
        }
        if (isEncryped) {
            fileName = fileName + StorageConstants.sEncryptedExtension;
        }
        return fileName;
    }

    public void mockFileExistence(String fileName, boolean isJson, boolean isEncrypted)
            throws IOException {
        fileThatExists = getTempFolder().newFile(constructFileName(fileName, isJson, isEncrypted));
        fileThatExists.createNewFile();
    }

    public void writeSerializableDataForRead() throws IOException {
        try(final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            final FileOutputStream fos = new FileOutputStream(getFileThatExists())) {
            oos.writeObject(getTestSerializableData());
            oos.flush();

            fos.write(baos.toByteArray());
        }

        setFis(new FileInputStream(getFileThatExists()));
    }

    public void writeJsonDataForRead() throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        byte[] bytes = objectMapper.writeValueAsBytes(getTestData());

        try(final FileOutputStream fos = new FileOutputStream(getFileThatExists())) {
            fos.write(bytes);
        }

        setFis(new FileInputStream(getFileThatExists()));
    }

    public void setFileName(String fileName, boolean isJson, boolean isEncryped) {
        this.fileName = constructFileName(fileName, isJson, isEncryped);
    }

    public String getFileName() {
        return fileName;
    }

    public File getFileThatExists() {
        return fileThatExists;
    }

    public TemporaryFolder getTempFolder() {
        return tempFolder;
    }

    public SecureTestData getSecureData() {
        return secureData;
    }

    public SecureTestSerializable getSecureSerializable() {
        return secureSerializable;
    }

    public TestData getTestData() {
        return testData;
    }

    public TestSerializableData getTestSerializableData() {
        return testSerializableData;
    }

    public BadSecureTestData getBadSecureTestData() {
        return badSecureTestData;
    }

    public FileInputStream getFis() {
        return fis;
    }

    public void setFis(FileInputStream fis) {
        this.fis = fis;
    }

    @Override
    public void close() throws Exception {
        if (fis != null) {
            fis.close();
        }
    }
}
