@load base/frameworks/notice

module X509_ext;

export {
    redef enum Notice::Type += {
        Suspicious_x509_Pattern,
    };
}

event log_x509_ext(rec: Info) {
    ## Start with the default values
    if ( rec$issuer_st == "Some-State" &&
         rec$issuer_o  == "Internet Widgits Pty Ltd" ) {
        NOTICE([$note=Suspicious_x509_Pattern,
                $msg=fmt("Suspicious x509 certificate with default values"),
                $fuid=rec$fuid]);   
    }
    if ( rec$issuer_l  == "Default City" &&
         rec$issuer_o  == "Default Company Ltd" ) {
        NOTICE([$note=Suspicious_x509_Pattern,
                $msg=fmt("Suspicious x509 certificate with default values"),
                $fuid=rec$fuid]);   
    }

    ## Copypasta from http://unix.stackexchange.com/questions/104171/create-ssl-certificate-non-interactively
    if ( rec$issuer_o  == "Dis" &&
         rec$issuer_l  == "Springfield" &&
         rec$issuer_st == "Denial" ) {
        NOTICE([$note=Suspicious_x509_Pattern,
                $msg=fmt("Certificate issuer matching Stack Overflow post pattern found"),
                $fuid=rec$fuid]);
    }
    if ( |rec$issuer_cn| == 24 &&
         |rec$issuer_l|  == 24 &&
         |rec$issuer_o|  == 24 &&
         rec$issuer_st   == "CN" ) {
        NOTICE([$note=Suspicious_x509_Pattern,
                $msg=fmt("Certificate issuer matching potentially malicious pattern found"),
                $fuid=rec$fuid]);
    }
 
    ## Ubiquiti routers, previously used as part of Dyre botnet   
    if ( rec$issuer_ou == "Technical Support" &&
         rec$issuer_o  == "Ubiquiti Networks Inc." ) {
        NOTICE([$note=Suspicious_x509_Pattern,
                $msg=fmt("Certificate issuer matching a Ubiquiti device found"),
                $fuid=rec$fuid]);
    }
    if ( rec$issuer_cn == "UBNT Router UI" &&
         rec$issuer_o  == "Ubiquiti Networks" ) {
        NOTICE([$note=Suspicious_x509_Pattern,
                $msg=fmt("Certificate issuer matching a Ubiquiti device found"),
                $fuid=rec$fuid]);
    }
}
