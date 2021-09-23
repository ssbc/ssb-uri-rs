// Test data
//
// Source: https://github.com/staltz/ssb-uri2/blob/8e8d3cf76fd3b68fe46e0338890df74457c3a036/test/fixtures.js

pub const MSG_URIS: [(&str, &str); 6] = [
    (
        "sigil",
        "%g3hPVPDEO1Aj/uPl0+J2NlhFB2bbFLIHlty+YuqFZ3w=.sha256",
    ),
    (
        "uri",
        "ssb:message/sha256/g3hPVPDEO1Aj_uPl0-J2NlhFB2bbFLIHlty-YuqFZ3w=",
    ),
    (
        "uri2",
        "ssb:message:sha256:g3hPVPDEO1Aj_uPl0-J2NlhFB2bbFLIHlty-YuqFZ3w=",
    ),
    (
        "uri3",
        "ssb://message/sha256/g3hPVPDEO1Aj_uPl0-J2NlhFB2bbFLIHlty-YuqFZ3w=",
    ),
    (
        "uri4",
        "ssb://message/bendybutt-v1/Z0rMVMDEO1Aj0uPl0_J2NlhFB2bbFLIHlty_YuqArFq=",
    ),
    (
        "uri5",
        "ssb:message/gabbygrove-v1/QibgMEFVrupoOpiILKVoNXnhzdVQVZf7dkmL9MSXO5g=",
    ),
];

pub const FEED_URIS: [(&str, &str); 6] = [
    (
        "sigil",
        "@+oaWWDs8g73EZFUMfW37R/ULtFEjwKN/DczvdYihjbU=.ed25519",
    ),
    (
        "uri",
        "ssb:feed/ed25519/-oaWWDs8g73EZFUMfW37R_ULtFEjwKN_DczvdYihjbU=",
    ),
    (
        "uri2",
        "ssb:feed:ed25519:-oaWWDs8g73EZFUMfW37R_ULtFEjwKN_DczvdYihjbU=",
    ),
    (
        "uri3",
        "ssb://feed/ed25519/-oaWWDs8g73EZFUMfW37R_ULtFEjwKN_DczvdYihjbU=",
    ),
    (
        "uri4",
        "ssb:feed/bendybutt-v1/APaWWDs8g73EZFUMfW37RBULtFEjwKNbDczvdYiRXtA=",
    ),
    (
        "uri5",
        "ssb:feed/gabbygrove-v1/FY5OG311W4j_KPh8H9B2MZt4WSziy_p-ABkKERJdujQ=",
    ),
];

pub const BLOB_URIS: [(&str, &str); 4] = [
    (
        "sigil",
        "&sbBmsB7XWvmIzkBzreYcuzPpLtpeCMDIs6n/OJGSC1U=.sha256",
    ),
    (
        "uri",
        "ssb:blob/sha256/sbBmsB7XWvmIzkBzreYcuzPpLtpeCMDIs6n_OJGSC1U=",
    ),
    (
        "uri2",
        "ssb:blob:sha256:sbBmsB7XWvmIzkBzreYcuzPpLtpeCMDIs6n_OJGSC1U=",
    ),
    (
        "uri3",
        "ssb://blob/sha256/sbBmsB7XWvmIzkBzreYcuzPpLtpeCMDIs6n_OJGSC1U=",
    ),
];

pub const ADDRESS_URIS: [(&str, &str); 4] = [
    ("multiserver", "net:wx.larpa.net:8008~shs:DTNmX+4SjsgZ7xyDh5xxmNtFqa6pWi5Qtw7cE8aR9TQ="),
    ("uri", "ssb:address/multiserver?multiserverAddress=net%3Awx.larpa.net%3A8008~shs%3ADTNmX%2B4SjsgZ7xyDh5xxmNtFqa6pWi5Qtw7cE8aR9TQ%3D"),
    ("uri2", "ssb:address:multiserver?multiserverAddress=net%3Awx.larpa.net%3A8008~shs%3ADTNmX%2B4SjsgZ7xyDh5xxmNtFqa6pWi5Qtw7cE8aR9TQ%3D"),
    ("uri3", "ssb://address/multiserver?multiserverAddress=net%3Awx.larpa.net%3A8008~shs%3ADTNmX%2B4SjsgZ7xyDh5xxmNtFqa6pWi5Qtw7cE8aR9TQ%3D"),
];

pub const EXPERIMENTAL_URIS: [(&str, &str); 2] = [
    ("httpInviteUri", "ssb://experimental/?action=claim-http-invite&invite=39c0ac1850ec9af14f1bb73&postTo=https%3A%2F%2Fscuttlebutt.eu%2Fclaiminvite"),
    ("httpInviteUri2", "ssb:experimental/?action=claim-http-invite&invite=39c0ac1850ec9af14f1bb73&postTo=https%3A%2F%2Fscuttlebutt.eu%2Fclaiminvite"),
];
