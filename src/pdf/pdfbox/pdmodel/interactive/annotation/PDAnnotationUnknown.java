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
package pdf.pdfbox.pdmodel.interactive.annotation;

import pdf.pdfbox.cos.COSDictionary;

/**
 * This is the class that represents an arbitary Unknown Annotation type.
 *
 * @author Paul King
 */
public class PDAnnotationUnknown extends PDAnnotation
{

    /**
     * Creates an arbitary annotation from a COSDictionary, expected to be a correct object definition for some sort of
     * annotation.
     *
     * @param dic The dictionary which represents this Annotation.
     */
    public PDAnnotationUnknown(COSDictionary dic)
    {
        super(dic);
    }
}
