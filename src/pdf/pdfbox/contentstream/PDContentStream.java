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

package pdf.pdfbox.contentstream;

import java.io.IOException;
import java.io.InputStream;

import pdf.pdfbox.pdmodel.PDResources;
import pdf.pdfbox.pdmodel.common.PDRectangle;
import pdf.pdfbox.util.Matrix;

/**
 * A content stream.
 *
 * @author John Hewson
 */
public interface PDContentStream
{
    /**
     * Returns this stream's content, if any.
     * 
     * @return An InputStream or null.
     * @throws IOException If the stream could not be read
     */
    InputStream getContents() throws IOException;

    /**
     * Returns this stream's resources, if any.
     * 
     * @return the resources of this stream.
     */
    PDResources getResources();

    /**
     * Returns the bounding box of the contents.
     * 
     * @return the bounding box of this stream.
     */
    PDRectangle getBBox();

    /**
     * Returns the matrix which transforms from the stream's space to user space.
     * 
     * @return the matrix of this stream.
     */
    Matrix getMatrix();
}
