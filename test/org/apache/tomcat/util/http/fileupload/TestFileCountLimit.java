/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.http.fileupload;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.http.fileupload.disk.DiskFileItemFactory;
import org.apache.tomcat.util.http.fileupload.impl.FileCountLimitExceededException;

/**
 * Verifies the fileCountMax guard added for CVE-2023-24998: a multipart
 * request containing more parts than the configured limit is rejected with a
 * {@link FileCountLimitExceededException} rather than being parsed in full.
 */
public class TestFileCountLimit {

    private static final String BOUNDARY = "boundary1234";

    private static byte[] buildMultipart(int partCount) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < partCount; i++) {
            sb.append("--").append(BOUNDARY).append("\r\n");
            sb.append("Content-Disposition: form-data; name=\"field").append(i)
                    .append("\"\r\n");
            sb.append("\r\n");
            sb.append("value").append(i).append("\r\n");
        }
        sb.append("--").append(BOUNDARY).append("--\r\n");
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static UploadContext newContext(final byte[] body) {
        return new UploadContext() {
            @Override
            public String getCharacterEncoding() {
                return StandardCharsets.ISO_8859_1.name();
            }

            @Override
            public String getContentType() {
                return "multipart/form-data; boundary=" + BOUNDARY;
            }

            @Override
            public InputStream getInputStream() {
                return new ByteArrayInputStream(body);
            }

            @Override
            public long contentLength() {
                return body.length;
            }
        };
    }

    private static FileUpload newUpload() {
        return new FileUpload(new DiskFileItemFactory());
    }

    @Test
    public void testUnderLimitParsesAll() throws Exception {
        FileUpload upload = newUpload();
        upload.setFileCountMax(3);
        List<FileItem> items = upload.parseRequest(newContext(buildMultipart(3)));
        Assert.assertEquals(3, items.size());
    }

    @Test
    public void testOverLimitRejected() throws Exception {
        FileUpload upload = newUpload();
        upload.setFileCountMax(3);
        try {
            upload.parseRequest(newContext(buildMultipart(4)));
            Assert.fail("Expected FileCountLimitExceededException");
        } catch (FileCountLimitExceededException e) {
            Assert.assertEquals(3, e.getLimit());
        }
    }

    @Test
    public void testNoLimitParsesAll() throws Exception {
        FileUpload upload = newUpload();
        // Default (-1) means no limit.
        Assert.assertEquals(-1, upload.getFileCountMax());
        List<FileItem> items = upload.parseRequest(newContext(buildMultipart(10)));
        Assert.assertEquals(10, items.size());
    }
}
