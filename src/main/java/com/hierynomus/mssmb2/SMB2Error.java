/*
 * Copyright (C)2016 - SMBJ Contributors
 *
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
package com.hierynomus.mssmb2;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * [MS-SMB2] 2.2.2 SMB2 ERROR Response
 */
public class SMB2Error {

    private List<SMB2ErrorData> errorData = new ArrayList<>();

    SMB2Error() {
    }

    SMB2Error read(SMB2Header header, SMBBuffer buffer) throws Buffer.BufferException {
        buffer.skip(2); // StructureSize (2 bytes)
        int errorContextCount = buffer.readByte(); // ErrorContextCount (1 byte)
        buffer.skip(1); // Reserved (1 byte)
        int byteCount = buffer.readUInt32AsInt(); // ByteCount (4 bytes)

        if (errorContextCount > 0) {
            readErrorContext(header, buffer, errorContextCount);
        } else if (byteCount > 0) {
            readErrorData(header, buffer);
        } else if (byteCount == 0) {
            buffer.skip(1); // ErrorData (1 byte)
        }

        return this;
    }

    /**
     * [MS-SMB2] 2.2.2.1 SMB2 ERROR Context Response
     *
     * @param header
     * @param buffer
     * @param errorContextCount
     * @throws Buffer.BufferException
     */
    private void readErrorContext(SMB2Header header, SMBBuffer buffer, int errorContextCount) throws Buffer.BufferException {
        for (int i = 0; i < errorContextCount; i++) {
            buffer.readUInt32AsInt(); // ErrorDataLength (4 bytes)
            buffer.skip(4); // ErrorId (always SMB2_ERROR_ID_DEFAULT (0x0)) (4 bytes)
            readErrorData(header, buffer);
        }
    }

    /**
     * [MS-SMB2] 2.2.2.2 ErrorData format
     *
     * @param header
     * @param buffer
     * @return
     * @throws Buffer.BufferException
     */
    private void readErrorData(SMB2Header header, SMBBuffer buffer) throws Buffer.BufferException {
        if (header.getStatus() == NtStatus.STATUS_BUFFER_TOO_SMALL) {
            this.errorData.add(new BufferTooSmallError().read(buffer));
        } else if (header.getStatus() == NtStatus.STATUS_STOPPED_ON_SYMLINK) {
            this.errorData.add(new SymbolicLinkError().read(buffer));
        }
    }

    public List<SMB2ErrorData> getErrorData() {
        return errorData;
    }

    interface SMB2ErrorData {
    }

    public static class SymbolicLinkError implements SMB2ErrorData {
        private boolean absolute;
        private int unparsedPathLength;
        private String substituteName;
        private String printName;

        private SymbolicLinkError() {
        }

        private SymbolicLinkError read(SMBBuffer buffer) throws Buffer.BufferException {
            int symLinkLength = buffer.readUInt32AsInt();// SymLinkLength (4 bytes)
            int endOfResponse = buffer.rpos() + symLinkLength;
            buffer.skip(4); // SymLinkErrorTag (4 bytes) (always 0x4C4D5953)
            buffer.skip(4); // ReparseTag (4 bytes) (always 0xA000000C)
            buffer.skip(2); // ReparseDataLength (2 bytes)
            unparsedPathLength = buffer.readUInt16(); // UnparsedPathLength (2 bytes)
            int substituteNameOffset = buffer.readUInt16(); // SubstituteNameOffset (2 bytes)
            int substituteNameLength = buffer.readUInt16(); // SubstituteNameLength (2 bytes)
            int printNameOffset = buffer.readUInt16(); // PrintNameOffset (2 bytes)
            int printNameLength = buffer.readUInt16(); // PrintNameLength (2 bytes)
            absolute = buffer.readUInt32() == 0; // Flags (4 bytes)
            substituteName = readOffsettedString(buffer, substituteNameOffset, substituteNameLength); // PathBuffer (variable)
            printName = readOffsettedString(buffer, printNameOffset, printNameLength); // PathBuffer (variable)
            buffer.rpos(endOfResponse); // Set buffer to the end of the response, so that we're aligned for any next response.
            return this;
        }

        private String readOffsettedString(SMBBuffer buffer, int offset, int length) throws Buffer.BufferException {
            int curpos = buffer.rpos();
            String s = null;
            if (length > 0) {
                buffer.rpos(curpos + offset);
                s = buffer.readString(StandardCharsets.UTF_16, length / 2);
            }
            buffer.rpos(curpos);
            return s;
        }

        public boolean isAbsolute() {
            return absolute;
        }

        public int getUnparsedPathLength() {
            return unparsedPathLength;
        }

        public String getSubstituteName() {
            return substituteName;
        }

        public String getPrintName() {
            return printName;
        }
    }

    
    /**
     * Apply the rules describe in <a href="https://msdn.microsoft.com/en-us/library/dd358040.aspx">
     * 2.2.2.2.1.1 Handling the Symbolic Link Error Response</a>
     * <p>
     * If the target of the symbolic link is absolute then the path returned in SubstituteName 
     * is formated as an absolute local NT Path, for example: "\??\D:\DonHall\MiscDocuments\PDocsD".<br>
     * In order to open the target path on the Share, we have to remove the NT Path prefix: \??\D:\
     * 
     * @see: https://googleprojectzero.blogspot.fr/2016/02/the-definitive-guide-on-win32-to-nt.html
     */    
    public static class SymbolicLinkResolver {
        private final static String WINDOWS_FILE_SEPARATOR = "\\";
        private final static String LINUX_FILE_SEPARATOR = "/";
        
        private final static String BEGIN = "^";
        private final static String SLASH = "\\\\";
        private final static String QUESTION_MARK = "\\?";
        private final static String COLON = "\\:";
        private final static String CAPTURE_DRIVE_LETTER = "([A-Z])";
        
        // prefix for native NT Path (for example: "\??\C:\"), must be removed to obtain a path usable with a share
        private final static String NT_PATH_PREFIX_REGEX = BEGIN + SLASH + QUESTION_MARK + QUESTION_MARK + SLASH + CAPTURE_DRIVE_LETTER + COLON + SLASH;
        private final static Pattern NT_PATH_PREFIX_PATTERN = Pattern.compile(NT_PATH_PREFIX_REGEX);
        
        private final SymbolicLinkError error;
        private final String targetPath;
        private final String driverLetter;
        
        public SymbolicLinkResolver(SymbolicLinkError error, String symlinkPath) {
            this.error = error;

            // length count bytes but encoding in SMB2 message is Unicode UTF-16
            int unparsedPathCharLength = error.getUnparsedPathLength() / 2;
            
            // The size, in bytes, of the unparsed portion is specified in the UnparsedPathLength field. 
            // The byte count MUST be used from the end of the path-name string and walked backward to find 
            // the starting location of the unparsed bytes.
            int unparsedPathPos = symlinkPath.length() - unparsedPathCharLength;
            String unparsedPath = symlinkPath.substring(unparsedPathPos);
            
            String substituteName = error.getSubstituteName();
            String driverLetter = "";
            if (error.isAbsolute()) {
                // In the case of an absolute path, the format returned in the substitute name is native Path NT (e.g beginning by "\??\C:\")
                Matcher ntPathMatcher = NT_PATH_PREFIX_PATTERN.matcher(substituteName);
                if (ntPathMatcher.find()) {
                    driverLetter = ntPathMatcher.group(1);
                    substituteName = substituteName.substring(ntPathMatcher.end());
                }                
                // If the SYMLINK_FLAG_RELATIVE flag is not set in the Flags field of the symbolic link error response, 
                // the unparsed portion of the file name MUST be appended to the substitute name to create the new target path name.
                // targetPath = substitute name concatenated with the unparsed portion of the file                
                targetPath = substituteName + WINDOWS_FILE_SEPARATOR + unparsedPath;
            } else {
                // If the SYMLINK_FLAG_RELATIVE flag is set in the Flags field of the symbolic link error response, 
                // the symbolic link name MUST be identified by backing up one path name element from the unparsed 
                // portion of the path name. The symbolic link MUST be replaced with the substitute name to create the new target path name.
                int symLinkNamePos = symlinkPath.lastIndexOf(WINDOWS_FILE_SEPARATOR, unparsedPathPos -1);
                String beginPath = symlinkPath.substring(0, symLinkNamePos);
                String workTargetPath = beginPath + WINDOWS_FILE_SEPARATOR + substituteName + WINDOWS_FILE_SEPARATOR + unparsedPath;
                // Because "." and ".." are not permitted as components of a path name to be sent over the wire, 
                // before reissuing the SMB2 CREATE request the client MUST first eliminate the ".." by normalizing the new target path name.
                targetPath = Paths.get(workTargetPath).normalize().toFile().getPath().replaceAll(LINUX_FILE_SEPARATOR, WINDOWS_FILE_SEPARATOR);
            }
            this.driverLetter = driverLetter;
        }

        public boolean isAbsolute() {
            return error.isAbsolute();
        }
        
        public String getTargetPath() {
            return targetPath;
        }
        
        public String getDriverLetter() {
            return driverLetter;
        }        
    }
    
    public static class BufferTooSmallError implements SMB2ErrorData {
        private long requiredBufferLength;

        private BufferTooSmallError() {
        }

        public BufferTooSmallError read(SMBBuffer buffer) throws Buffer.BufferException {
            this.requiredBufferLength = buffer.readUInt32(); // minimum required buffer size
            return this;
        }

        public long getRequiredBufferLength() {
            return requiredBufferLength;
        }
    }
}
