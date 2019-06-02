package edu.uw.medhas.mhealthsecurityframework.storage.cache;

import junit.framework.Assert;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.FileNotFoundException;
import java.util.UUID;

import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureData;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureSerializable;
import edu.uw.medhas.mhealthsecurityframework.storage.SecureTestData;
import edu.uw.medhas.mhealthsecurityframework.storage.TestData;
import edu.uw.medhas.mhealthsecurityframework.storage.TestSerializableData;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;

/**
 * Created by medhas on 11/3/18.
 */

public class SecureCacheHandlerTest {
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private String fileName = UUID.randomUUID().toString();

    private SecureCacheHandler fileHandler;

    private CacheStorageMockContext context;

    @Before
    public void setup() {
        context = new CacheStorageMockContext(tempFolder);
        fileHandler = new SecureCacheHandler(context);
    }

    @After
    public void tearDown() throws Exception {
        context.close();
    }

    @Test(expected = SerializationException.class)
    public void writeData_secureData_serializationException() throws Exception {
        context.setFileName(fileName, true, true);
        context.mockFosIOException();
        fileHandler.writeData(context.getSecureData(), fileName);
    }

    @Test(expected = NoDefaultConstructorException.class)
    public void writeData_badSecureData_noDefaultConstructorException() throws Exception {
        fileHandler.writeData(context.getBadSecureTestData(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_secureData() throws Exception {
        context.setFileName(fileName, true, true);
        fileHandler.writeData(context.getSecureData(), fileName);
    }

    @Test(expected = SerializationException.class)
    public void writeData_secureSerializable_serializationException() throws Exception {
        context.setFileName(fileName, false, true);
        context.mockFosIOException();
        fileHandler.writeData(context.getSecureSerializable(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_secureSerializableData() throws Exception {
        context.setFileName(fileName, false, true);
        fileHandler.writeData(context.getSecureSerializable(), fileName);
    }

    @Test(expected = SerializationException.class)
    public void writeData_data_serializationException() throws Exception {
        context.setFileName(fileName, true, false);
        context.mockFosIOException();
        fileHandler.writeData(context.getTestData(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_data() throws Exception {
        context.setFileName(fileName, true, false);
        fileHandler.writeData(context.getTestData(), fileName);
    }

    @Test(expected = SerializationException.class)
    public void writeData_serializable_serializationException() throws Exception {
        context.setFileName(fileName, false, false);
        context.mockFosIOException();fileHandler.writeData(context.getTestSerializableData(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_serializableData() throws Exception {
        context.setFileName(fileName, false, false);
        fileHandler.writeData(context.getTestSerializableData(), fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_jsonEncrypted_fileNotFoundException() throws Exception {
        context.setFileName(fileName, true, true);
        context.mockFileExistence(fileName, true, true);
        context.setInvalidEnvDirectoryThreshold(2);
        fileHandler.readData(SecureData.class, fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_json_fileNotFoundException() throws Exception {
        context.setFileName(fileName, true, false);
        context.mockFileExistence(fileName, true, false);
        context.setInvalidEnvDirectoryThreshold(3);
        fileHandler.readData(TestData.class, fileName);
    }

    @Test(expected = SerializationException.class)
    public void readData_json_serializationException() throws Exception {
        context.setFileName(fileName, true, false);
        context.mockFileExistence(fileName, true, false);
        fileHandler.readData(TestData.class, fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_encrypted_fileNotFoundException() throws Exception {
        context.setFileName(fileName, false, true);
        context.mockFileExistence(fileName, false, true);
        context.setInvalidEnvDirectoryThreshold(4);
        fileHandler.readData(SecureSerializable.class, fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_serializable_fileNotFoundException() throws Exception {
        context.setFileName(fileName, false, false);
        fileHandler.readData(TestSerializableData.class, fileName);
    }

    @Test(expected = SerializationException.class)
    public void readData_serializable_serializationException() throws Exception {
        context.setFileName(fileName, false, false);
        context.mockFileExistence(fileName, false, false);
        fileHandler.readData(TestSerializableData.class, fileName);
    }

    @Test(expected = Test.None.class)
    public void readData_serializable() throws Exception {
        context.mockFileExistence(fileName, false, false);
        context.writeSerializableDataForRead();
        fileHandler.readData(TestSerializableData.class, fileName);
    }

    @Test
    public void readData_json() throws Exception {
        context.mockFileExistence(fileName, true, false);
        context.writeJsonDataForRead();
        final TestSerializableData foundData = fileHandler.readData(TestSerializableData.class, fileName);
        Assert.assertEquals(context.getTestData().getData(), foundData.getData());
    }

    @Test(expected = Test.None.class)
    public void write_read_secureData() throws Exception {
        context.setFileName(fileName, true, true);
        fileHandler.writeData(context.getSecureData(), fileName);

        final SecureTestData foundData = fileHandler.readData(SecureTestData.class, fileName);
        Assert.assertEquals(context.getSecureData().getData(), foundData.getData());
    }
}
