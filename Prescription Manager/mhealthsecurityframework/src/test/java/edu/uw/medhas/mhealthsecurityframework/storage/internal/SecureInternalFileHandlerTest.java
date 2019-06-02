package edu.uw.medhas.mhealthsecurityframework.storage.internal;

import android.content.Context;

import junit.framework.Assert;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.UUID;

import edu.uw.medhas.mhealthsecurityframework.storage.metadata.model.SecureSerializable;
import edu.uw.medhas.mhealthsecurityframework.storage.SecureTestData;
import edu.uw.medhas.mhealthsecurityframework.storage.TestData;
import edu.uw.medhas.mhealthsecurityframework.storage.TestSerializableData;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.NoDefaultConstructorException;
import edu.uw.medhas.mhealthsecurityframework.storage.exception.SerializationException;


/**
 * Created by medhasrivastava on 11/2/18.
 */

public class SecureInternalFileHandlerTest {
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private String fileName = UUID.randomUUID().toString();

    private SecureInternalFileHandler fileHandler;

    private InternalStorageMockContext context;

    @Before
    public void setup() {
        context = new InternalStorageMockContext(Context.MODE_PRIVATE, tempFolder);
        fileHandler = new SecureInternalFileHandler(context);
    }

    @After
    public void tearDown() throws Exception {
        context.close();
    }

    @Test(expected = SerializationException.class)
    public void writeData_secureData_serializationException() throws Exception {
        context.setFileName(fileName, true, true);
        context.mockFosWrite(new IOException());
        fileHandler.writeData(context.getSecureData(), fileName);
    }

    @Test(expected = NoDefaultConstructorException.class)
    public void writeData_badSecureData_noDefaultConstructorException() throws Exception {
        fileHandler.writeData(context.getBadSecureTestData(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_secureData() throws Exception {
        context.setFileName(fileName, true, true);
        context.mockFosWrite(null);
        fileHandler.writeData(context.getSecureData(), fileName);
    }

    @Test(expected = SerializationException.class)
    public void writeData_secureSerializable_serializationException() throws Exception {
        context.setFileName(fileName, false, true);
        context.mockFosWrite(new IOException());
        fileHandler.writeData(context.getSecureSerializable(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_secureSerializableData() throws Exception {
        context.setFileName(fileName, false, true);
        context.mockFosWrite(null);
        fileHandler.writeData(context.getSecureSerializable(), fileName);
    }

    @Test(expected = SerializationException.class)
    public void writeData_data_serializationException() throws Exception {
        context.setFileName(fileName, true, false);
        context.mockFosWrite(new IOException());

        fileHandler.writeData(context.getTestData(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_data() throws Exception {
        context.setFileName(fileName, true, false);
        context.mockFosWrite(null);

        fileHandler.writeData(context.getTestData(), fileName);
    }

    @Test(expected = SerializationException.class)
    public void writeData_serializable_serializationException() throws Exception {
        context.setFileName(fileName, false, false);
        context.mockFosWrite(new IOException());

        fileHandler.writeData(context.getTestSerializableData(), fileName);
    }

    @Test(expected = Test.None.class)
    public void writeData_serializableData() throws Exception {
        context.setFileName(fileName, false, false);
        context.mockFosWrite(null);

        fileHandler.writeData(context.getTestSerializableData(), fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_jsonEncrypted_fileNotFoundException() throws Exception {
        context.mockFileExistence(fileName, true, true);
        fileHandler.readData(SecureTestData.class, fileName);
    }

    @Test(expected = SerializationException.class)
    public void readData_jsonEncrypted_serializationException() throws Exception {
        context.mockFileExistence(fileName, true, true);
        context.mockFisIOException();
        fileHandler.readData(SecureTestData.class, fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_json_fileNotFoundException() throws Exception {
        context.mockFileExistence(fileName, true, false);
        fileHandler.readData(TestData.class, fileName);
    }

    @Test(expected = SerializationException.class)
    public void readData_json_serializationException() throws Exception {
        context.mockFileExistence(fileName, true, false);
        context.mockFisIOException();
        fileHandler.readData(TestData.class, fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_encrypted_fileNotFoundException() throws Exception {
        context.mockFileExistence(fileName, false, true);
        fileHandler.readData(SecureSerializable.class, fileName);
    }

    @Test(expected = SerializationException.class)
    public void readData_encrypted_serializationException() throws Exception {
        context.mockFileExistence(fileName, false, true);
        context.mockFisIOException();
        fileHandler.readData(SecureSerializable.class, fileName);
    }

    @Test(expected = FileNotFoundException.class)
    public void readData_serializable_fileNotFoundException() throws Exception {
        context.mockFileExistence(fileName, false, false);
        fileHandler.readData(TestSerializableData.class, fileName);
    }

    @Test(expected = SerializationException.class)
    public void readData_serializable_serializationException() throws Exception {
        context.mockFileExistence(fileName, false, false);
        context.mockFisIOException();
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
}
