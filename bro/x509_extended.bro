@load base/frameworks/files
@load base/files/hash

module X509_ext;

export {
    redef enum Log::ID += { LOG };
 
    type Info: record {
        fuid:             string &log;
        sha1:             string &log;
        subject_c:        string &log &optional;
        subject_cn:       string &log &optional;
        subject_l:        string &log &optional;
        subject_o:        string &log &optional;
        subject_ou:       string &log &optional;
        subject_st:       string &log &optional;
        subject_email:    string &log &optional;
        subject_unstruct: string &log &optional;
        subject_serial:   string &log &optional;

        issuer_c:         string &log &optional;
        issuer_cn:        string &log &optional;
        issuer_l:         string &log &optional;
        issuer_o:         string &log &optional;
        issuer_ou:        string &log &optional; 
        issuer_st:        string &log &optional;
        issuer_email:     string &log &optional;
        issuer_unstruct:  string &log &optional;
        issuer_serial:    string &log &optional;
    };

    global log_x509_ext: event(rec: Info);
}

redef record X509::Info += {
    parsed: Info &optional;
};

event bro_init() &priority=5 {
    Log::create_stream(X509_ext::LOG, [$columns=Info, $ev=log_x509_ext, $path="x509_extended"]);
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5 {
    if ( !f$info$x509?$parsed ) {
        local tmp: Info;
        tmp$fuid = f$info$fuid;
        f$info$x509$parsed = tmp; 
    }
    local issuer_enc = subst_string(subst_string(cert$issuer, "\\,", "\x11"), "\\/", "\x12");
    local pairs = split_string(issuer_enc, /[,\/]/);
    for ( pair in pairs ) {
        local pairs_dec = subst_string(subst_string(pairs[pair], "\x11", "\\,"), "\x12", "\\/");
        local fields = split_string1(pairs_dec, /=/);
        if ( |fields| == 2 ) {
            if ( fields[0] == "C" ) {
                f$info$x509$parsed$issuer_c = fields[1];
            } else if ( fields[0] == "CN" ) {
                f$info$x509$parsed$issuer_cn = fields[1];
            } else if ( fields[0] == "L" ) {
                f$info$x509$parsed$issuer_l = fields[1];
            } else if ( fields[0] == "O" ) {
                f$info$x509$parsed$issuer_o = fields[1];
            } else if ( fields[0] == "OU" ) {
                f$info$x509$parsed$issuer_ou = fields[1];
            } else if ( fields[0] == "ST" ) {
                f$info$x509$parsed$issuer_st = fields[1];
            } else if ( fields[0] == "emailAddress" ) {
                f$info$x509$parsed$issuer_email = fields[1];
            } else if ( fields[0] == "unstructuredName" ) {
                f$info$x509$parsed$issuer_unstruct = fields[1];
            } else if ( fields[0] == "serialNumber" ) {
                f$info$x509$parsed$issuer_serial = fields[1];
            }
        }
    }

    local subject_enc = subst_string(subst_string(cert$subject, "\\,", "\x11"), "\\/", "\x12");
    pairs = split_string(subject_enc, /[,\/]/);
    for ( pair in pairs ) {
        pairs_dec = subst_string(subst_string(pairs[pair], "\x11", "\\,"), "\x12", "\\/");
        fields = split_string1(pairs_dec, /=/);
        if ( |fields| == 2 ) {
            if ( fields[0] == "C" ) {
                f$info$x509$parsed$subject_c = fields[1];
            } else if ( fields[0] == "CN" ) {
                f$info$x509$parsed$subject_cn = fields[1];
            } else if ( fields[0] == "L" ) {
                f$info$x509$parsed$subject_l = fields[1];
            } else if ( fields[0] == "O" ) {
                f$info$x509$parsed$subject_o = fields[1];
            } else if ( fields[0] == "OU" ) {
                f$info$x509$parsed$subject_ou = fields[1];
            } else if ( fields[0] == "ST" ) {
                f$info$x509$parsed$subject_st = fields[1];
            } else if ( fields[0] == "emailAddress" ) {
                f$info$x509$parsed$subject_email = fields[1];
            } else if ( fields[0] == "unstructuredName" ) {
                f$info$x509$parsed$subject_unstruct = fields[1];
            } else if ( fields[0] == "serialNumber" ) {
                f$info$x509$parsed$subject_serial = fields[1];
            }
        }
    }
}

event file_state_remove(f: fa_file) &priority=6 {
    if ( ! f$info?$x509 || ! f$info$x509?$parsed )
        return;
 
    f$info$x509$parsed$sha1 = f$info$sha1;
   
    Log::write(LOG, f$info$x509$parsed);
}
