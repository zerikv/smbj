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

import com.hierynomus.mssmb2.SMB2Error.SymbolicLinkError;
import com.hierynomus.mssmb2.SMB2Error.SymbolicLinkResolver;

@SuppressWarnings("serial")
public class SymbolicLinkException extends SMBApiException {
    
    private final String symlinkPath;
    private final SymbolicLinkResolver symlinkResolver;
    
    public SymbolicLinkException(String cmdName, Object symlinkPath, SMB2Packet resp) {
        super(resp.getHeader(), cmdName + " for symlink " + symlinkPath);
        SymbolicLinkError error = (SymbolicLinkError)resp.getError().getErrorData().get(0);
        this.symlinkPath = symlinkPath.toString();
        
        symlinkResolver = new SymbolicLinkResolver(error, this.symlinkPath);
    }
    
    public String getSymlinkPath() {
        return symlinkPath;
    }
    
    public String getTargetPath() {
        return symlinkResolver.getTargetPath();
    }
    
    public boolean isAbsolute() {
        return symlinkResolver.isAbsolute();
    }
    
    public String getAdminShareName() {
        return isAbsolute() ? symlinkResolver.getDriverLetter() + "$" : "";
    }
}