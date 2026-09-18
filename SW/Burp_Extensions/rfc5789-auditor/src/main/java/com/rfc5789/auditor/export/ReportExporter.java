/*
 * Copyright 2024 RFC 5789 Auditor Contributors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.rfc5789.auditor.export;

import com.rfc5789.auditor.model.Finding;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Strategy interface for exporting findings to a file.
 *
 * <p>Implementations write the given findings list to the specified output
 * file in a format-specific representation (JSON, Markdown, etc.).</p>
 */
public interface ReportExporter {

    /**
     * Exports the given findings to the specified file.
     *
     * @param findings   the findings to export; must not be null
     * @param outputFile the destination file; will be created or overwritten
     * @throws IOException if an I/O error occurs during writing
     */
    void export(List<Finding> findings, File outputFile) throws IOException;
}
