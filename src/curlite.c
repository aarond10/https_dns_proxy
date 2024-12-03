/*
 * This file is modified from curl 8.11.1,
 * Some of the structures are modified to adapt this project.
 * The main purpose of this file is to provide `curl_url_xx` series
 *   functions that introduced in curl 7.62.0.
 * With curlite.c/curlite.h, this project is able to compile with
 *   libcurl 7.55.0.
 * When the libcurl version is equal or above 7.62.0, it will use the
 *   new library or this file is compiled to prvoide missing functions.
 * Lower the libcur dependency extended this project's adaptable scenarios,
 *   some of old systems, OpenWRT for example, is usually shipped
 *   with old version of libcurl.
 */
#include "curlite.h"

#ifdef USE_CURLITE
/*
 * FILE scheme handler.
 */
const struct Curl_handler Curl_handler_file = {
  "file",                               /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  0,                                    /* defport */
  CURLPROTO_FILE,                       /* protocol */
  CURLPROTO_FILE,                       /* family */
  PROTOPT_NONETWORK | PROTOPT_NOURLQUERY /* flags */
};

/*
 * SMTP protocol handler.
 */
const struct Curl_handler Curl_handler_smtp = {
  "smtp",                           /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                        /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_SMTP,                        /* defport */
  CURLPROTO_SMTP,                   /* protocol */
  CURLPROTO_SMTP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | /* flags */
  PROTOPT_URLOPTIONS
};
const struct Curl_handler Curl_handler_sftp = {
  "SFTP",                               /* scheme */
  ZERO_NULL,               /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                        /* connect_it */
  ZERO_NULL,                /* connecting */
  ZERO_NULL,                           /* doing */
  ZERO_NULL,                        /* proto_getsock */
  ZERO_NULL,                        /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_SSH,                             /* defport */
  CURLPROTO_SFTP,                       /* protocol */
  CURLPROTO_SFTP,                       /* family */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION
  | PROTOPT_NOURLQUERY                  /* flags */
};
const struct Curl_handler Curl_handler_smb = {
  "smb",                                /* scheme */
  ZERO_NULL,                 /* setup_connection */
  ZERO_NULL,                               /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                          /* connect_it */
  ZERO_NULL,                 /* connecting */
  ZERO_NULL,                    /* doing */
  ZERO_NULL,                          /* proto_getsock */
  ZERO_NULL,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                       /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_SMB,                             /* defport */
  CURLPROTO_SMB,                        /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_NONE                          /* flags */
};
const struct Curl_handler Curl_handler_smtps = {
  "smtps",                          /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                        /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_SMTPS,                       /* defport */
  CURLPROTO_SMTPS,                  /* protocol */
  CURLPROTO_SMTP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL
  | PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS /* flags */
};

/*
 * TELNET protocol handler.
 */
const struct Curl_handler Curl_handler_telnet = {
  "telnet",                             /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                          /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_TELNET,                          /* defport */
  CURLPROTO_TELNET,                     /* protocol */
  CURLPROTO_TELNET,                     /* family */
  PROTOPT_NONE | PROTOPT_NOURLQUERY     /* flags */
};

/*
 * Gopher protocol handler.
 * This is also a nice simple template to build off for simple
 * connect-command-download protocols.
 */
const struct Curl_handler Curl_handler_gopher = {
  "gopher",                             /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_GOPHER,                          /* defport */
  CURLPROTO_GOPHER,                     /* protocol */
  CURLPROTO_GOPHER,                     /* family */
  PROTOPT_NONE                          /* flags */
};
const struct Curl_handler Curl_handler_gophers = {
  "gophers",                            /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                       /* connect_it */
  ZERO_NULL,                    /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_GOPHER,                          /* defport */
  CURLPROTO_GOPHERS,                    /* protocol */
  CURLPROTO_GOPHER,                     /* family */
  PROTOPT_SSL                           /* flags */
};
const struct Curl_handler Curl_handler_rtmpe = {
  "rtmpe",                              /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTMP,                            /* defport */
  CURLPROTO_RTMPE,                      /* protocol */
  CURLPROTO_RTMPE,                      /* family */
  PROTOPT_NONE                          /* flags */
};

/*
 * TFTP protocol handler.
 */
const struct Curl_handler Curl_handler_tftp = {
  "tftp",                               /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                 /* connecting */
  ZERO_NULL,                           /* doing */
  ZERO_NULL,                         /* proto_getsock */
  ZERO_NULL,                         /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_TFTP,                            /* defport */
  CURLPROTO_TFTP,                       /* protocol */
  CURLPROTO_TFTP,                       /* family */
  PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY /* flags */
};

/*
 * IMAP protocol handler.
 */
const struct Curl_handler Curl_handler_imap = {
  "imap",                           /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                        /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_IMAP,                        /* defport */
  CURLPROTO_IMAP,                   /* protocol */
  CURLPROTO_IMAP,                   /* family */
  PROTOPT_CLOSEACTION|              /* flags */
  PROTOPT_URLOPTIONS
};
const struct Curl_handler Curl_handler_rtmps = {
  "rtmps",                              /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTMPS,                           /* defport */
  CURLPROTO_RTMPS,                      /* protocol */
  CURLPROTO_RTMP,                       /* family */
  PROTOPT_NONE                          /* flags */
};
const struct Curl_handler Curl_handler_rtmpt = {
  "rtmpt",                              /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTMPT,                           /* defport */
  CURLPROTO_RTMPT,                      /* protocol */
  CURLPROTO_RTMPT,                      /* family */
  PROTOPT_NONE                          /* flags */
};

/*
 * IMAPS protocol handler.
 */
const struct Curl_handler Curl_handler_imaps = {
  "imaps",                          /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                        /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_IMAPS,                       /* defport */
  CURLPROTO_IMAPS,                  /* protocol */
  CURLPROTO_IMAP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL | /* flags */
  PROTOPT_URLOPTIONS
};

/*
 * RTSP handler interface.
 */
const struct Curl_handler Curl_handler_rtsp = {
  "rtsp",                               /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                  /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                       /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTSP,                            /* defport */
  CURLPROTO_RTSP,                       /* protocol */
  CURLPROTO_RTSP,                       /* family */
  PROTOPT_NONE                          /* flags */
};
const struct Curl_handler Curl_handler_smbs = {
  "smbs",                               /* scheme */
  ZERO_NULL,                 /* setup_connection */
  ZERO_NULL,                               /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                          /* connect_it */
  ZERO_NULL,                 /* connecting */
  ZERO_NULL,                    /* doing */
  ZERO_NULL,                          /* proto_getsock */
  ZERO_NULL,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                       /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_SMBS,                            /* defport */
  CURLPROTO_SMBS,                       /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_SSL                           /* flags */
};
const struct Curl_handler Curl_handler_scp = {
  "SCP",                        /* scheme */
  ZERO_NULL,       /* setup_connection */
  ZERO_NULL,                  /* do_it */
  ZERO_NULL,                     /* done */
  ZERO_NULL,                    /* do_more */
  ZERO_NULL,                /* connect_it */
  ZERO_NULL,        /* connecting */
  ZERO_NULL,                    /* doing */
  ZERO_NULL,                /* proto_getsock */
  ZERO_NULL,                /* doing_getsock */
  ZERO_NULL,                    /* domore_getsock */
  ZERO_NULL,                /* perform_getsock */
  ZERO_NULL,               /* disconnect */
  ZERO_NULL,                    /* write_resp */
  ZERO_NULL,                    /* write_resp_hd */
  ZERO_NULL,                    /* connection_check */
  ZERO_NULL,                    /* attach connection */
  PORT_SSH,                     /* defport */
  CURLPROTO_SCP,                /* protocol */
  CURLPROTO_SCP,                /* family */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY    /* flags */
};

/*
 * POP3 protocol handler.
 */
const struct Curl_handler Curl_handler_pop3 = {
  "pop3",                           /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                        /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                       /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_POP3,                        /* defport */
  CURLPROTO_POP3,                   /* protocol */
  CURLPROTO_POP3,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | /* flags */
  PROTOPT_URLOPTIONS
};
const struct Curl_handler Curl_handler_rtmp = {
  "rtmp",                               /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTMP,                            /* defport */
  CURLPROTO_RTMP,                       /* protocol */
  CURLPROTO_RTMP,                       /* family */
  PROTOPT_NONE                          /* flags */
};
const struct Curl_handler Curl_handler_rtmpte = {
  "rtmpte",                             /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTMPT,                           /* defport */
  CURLPROTO_RTMPTE,                     /* protocol */
  CURLPROTO_RTMPTE,                     /* family */
  PROTOPT_NONE                          /* flags */
};

/*
 * POP3S protocol handler.
 */
const struct Curl_handler Curl_handler_pop3s = {
  "pop3s",                          /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                        /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                       /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_POP3S,                       /* defport */
  CURLPROTO_POP3S,                  /* protocol */
  CURLPROTO_POP3,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL
  | PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS /* flags */
};
/*
 * DICT protocol handler.
 */
const struct Curl_handler Curl_handler_dict = {
  "dict",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_DICT,                            /* defport */
  CURLPROTO_DICT,                       /* protocol */
  CURLPROTO_DICT,                       /* family */
  PROTOPT_NONE | PROTOPT_NOURLQUERY     /* flags */
};

/*
 * MQTT protocol handler.
 */
const struct Curl_handler Curl_handler_mqtt = {
  "mqtt",                             /* scheme */
  ZERO_NULL,                    /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                          /* done */
  ZERO_NULL,                          /* do_more */
  ZERO_NULL,                          /* connect_it */
  ZERO_NULL,                          /* connecting */
  ZERO_NULL,                         /* doing */
  ZERO_NULL,                          /* proto_getsock */
  ZERO_NULL,                       /* doing_getsock */
  ZERO_NULL,                          /* domore_getsock */
  ZERO_NULL,                          /* perform_getsock */
  ZERO_NULL,                          /* disconnect */
  ZERO_NULL,                          /* write_resp */
  ZERO_NULL,                          /* write_resp_hd */
  ZERO_NULL,                          /* connection_check */
  ZERO_NULL,                          /* attach connection */
  PORT_MQTT,                          /* defport */
  CURLPROTO_MQTT,                     /* protocol */
  CURLPROTO_MQTT,                     /* family */
  PROTOPT_NONE                        /* flags */
};

const struct Curl_handler Curl_handler_ws = {
  "WS",                                 /* scheme */
  ZERO_NULL,                        /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                    /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                        /* disconnect */
  ZERO_NULL,                 /* write_resp */
  ZERO_NULL,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTP,                            /* defport */
  CURLPROTO_WS,                         /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};
const struct Curl_handler Curl_handler_rtmpts = {
  "rtmpts",                             /* scheme */
  ZERO_NULL,                /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                      /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTMPS,                           /* defport */
  CURLPROTO_RTMPTS,                     /* protocol */
  CURLPROTO_RTMPT,                      /* family */
  PROTOPT_NONE                          /* flags */
};

const struct Curl_handler Curl_handler_wss = {
  "WSS",                                /* scheme */
  ZERO_NULL,                        /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                    /* connect_it */
  ZERO_NULL,                                 /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                                 /* proto_getsock */
  ZERO_NULL,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                        /* disconnect */
  ZERO_NULL,                 /* write_resp */
  ZERO_NULL,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_WSS,                        /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | /* flags */
  PROTOPT_USERPWDCTRL
};

/*
 * LDAP protocol handler.
 */
const struct Curl_handler Curl_handler_ldap = {
  "ldap",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_LDAP,                            /* defport */
  CURLPROTO_LDAP,                       /* protocol */
  CURLPROTO_LDAP,                       /* family */
  PROTOPT_NONE                          /* flags */
};

/*
 * LDAPS protocol handler.
 */
const struct Curl_handler Curl_handler_ldaps = {
  "ldaps",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_LDAPS,                           /* defport */
  CURLPROTO_LDAPS,                      /* protocol */
  CURLPROTO_LDAP,                       /* family */
  PROTOPT_SSL                           /* flags */
};

/*
 * FTP protocol handler.
 */
const struct Curl_handler Curl_handler_ftp = {
  "ftp",                           /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                     /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,              /* domore_getsock */
  ZERO_NULL,                       /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                       /* write_resp */
  ZERO_NULL,                       /* write_resp_hd */
  ZERO_NULL,                       /* connection_check */
  ZERO_NULL,                       /* attach connection */
  PORT_FTP,                        /* defport */
  CURLPROTO_FTP,                   /* protocol */
  CURLPROTO_FTP,                   /* family */
  PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD |
  PROTOPT_NOURLQUERY | PROTOPT_PROXY_AS_HTTP |
  PROTOPT_WILDCARD /* flags */
};

/*
 * FTPS protocol handler.
 */
const struct Curl_handler Curl_handler_ftps = {
  "ftps",                          /* scheme */
  ZERO_NULL,            /* setup_connection */
  ZERO_NULL,                          /* do_it */
  ZERO_NULL,                        /* done */
  ZERO_NULL,                     /* do_more */
  ZERO_NULL,                     /* connect_it */
  ZERO_NULL,             /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                     /* proto_getsock */
  ZERO_NULL,                     /* doing_getsock */
  ZERO_NULL,              /* domore_getsock */
  ZERO_NULL,                       /* perform_getsock */
  ZERO_NULL,                  /* disconnect */
  ZERO_NULL,                       /* write_resp */
  ZERO_NULL,                       /* write_resp_hd */
  ZERO_NULL,                       /* connection_check */
  ZERO_NULL,                       /* attach connection */
  PORT_FTPS,                       /* defport */
  CURLPROTO_FTPS,                  /* protocol */
  CURLPROTO_FTP,                   /* family */
  PROTOPT_SSL | PROTOPT_DUAL | PROTOPT_CLOSEACTION |
  PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY | PROTOPT_WILDCARD /* flags */
};

/*
 * HTTP handler interface.
 */
const struct Curl_handler Curl_handler_http = {
  "http",                               /* scheme */
  ZERO_NULL,                 /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                    /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                 /* write_resp */
  ZERO_NULL,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};
/*
 * HTTPS handler interface.
 */
const struct Curl_handler Curl_handler_https = {
  "https",                              /* scheme */
  ZERO_NULL,                 /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                    /* connect_it */
  ZERO_NULL,                                 /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                                 /* proto_getsock */
  ZERO_NULL,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                 /* write_resp */
  ZERO_NULL,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN | /* flags */
  PROTOPT_USERPWDCTRL
};

/* the provided input number is 1-based but this returns the number 0-based.

   returns -1 if no valid number was provided.
*/
static int dollarstring(char *input, char **end)
{
  if(ISDIGIT(*input)) {
    int number = 0;
    do {
      if(number < MAX_PARAMETERS) {
        number *= 10;
        number += *input - '0';
      }
      input++;
    } while(ISDIGIT(*input));

    if(number && (number <= MAX_PARAMETERS) && ('$' == *input)) {
      *end = ++input;
      return number - 1;
    }
  }
  return -1;
}

/*
 * Init a dynbuf struct.
 */
void Curl_dyn_init(struct dynbuf *s, size_t toobig)
{
  DEBUGASSERT(s);
  DEBUGASSERT(toobig);
  s->bufr = NULL;
  s->leng = 0;
  s->allc = 0;
  s->toobig = toobig;
#ifdef DEBUGBUILD
  s->init = DYNINIT;
#endif
}

/*
 * free the buffer and re-init the necessary fields. It does not touch the
 * 'init' field and thus this buffer can be reused to add data to again.
 */
void Curl_dyn_free(struct dynbuf *s)
{
  DEBUGASSERT(s);
  Curl_safefree(s->bufr);
  s->leng = s->allc = 0;
}

/*
 * Returns a pointer to the buffer.
 */
char *Curl_dyn_ptr(const struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return s->bufr;
}

/*
 * Returns the length of the buffer.
 */
size_t Curl_dyn_len(const struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return s->leng;
}

/*
 * Store/append an chunk of memory to the dynbuf.
 */
static CURLcode dyn_nappend(struct dynbuf *s,
                            const unsigned char *mem, size_t len)
{
  size_t indx = s->leng;
  size_t a = s->allc;
  size_t fit = len + indx + 1; /* new string + old string + zero byte */

  /* try to detect if there is rubbish in the struct */
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(s->toobig);
  DEBUGASSERT(indx < s->toobig);
  DEBUGASSERT(!s->leng || s->bufr);
  DEBUGASSERT(a <= s->toobig);
  DEBUGASSERT(!len || mem);

  if(fit > s->toobig) {
    Curl_dyn_free(s);
    return CURLE_TOO_LARGE;
  }
  else if(!a) {
    DEBUGASSERT(!indx);
    /* first invoke */
    if(MIN_FIRST_ALLOC > s->toobig)
      a = s->toobig;
    else if(fit < MIN_FIRST_ALLOC)
      a = MIN_FIRST_ALLOC;
    else
      a = fit;
  }
  else {
    while(a < fit)
      a *= 2;
    if(a > s->toobig)
      /* no point in allocating a larger buffer than this is allowed to use */
      a = s->toobig;
  }

  if(a != s->allc) {
    /* this logic is not using Curl_saferealloc() to make the tool not have to
       include that as well when it uses this code */
    void *p = realloc(s->bufr, a);
    if(!p) {
      Curl_dyn_free(s);
      return CURLE_OUT_OF_MEMORY;
    }
    s->bufr = p;
    s->allc = a;
  }

  if(len)
    memcpy(&s->bufr[indx], mem, len);
  s->leng = indx + len;
  s->bufr[s->leng] = 0;
  return CURLE_OK;
}

/*
 * Appends a buffer with length.
 */
CURLcode Curl_dyn_addn(struct dynbuf *s, const void *mem, size_t len)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return dyn_nappend(s, mem, len);
}

char *curl_mvaprintf(const char *format, va_list ap_save);
/*
 * Append a string vprintf()-style
 */
CURLcode Curl_dyn_vaddf(struct dynbuf *s, const char *fmt, va_list ap)
{
#ifdef BUILDING_LIBCURL
  int rc;
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  DEBUGASSERT(fmt);
  rc = Curl_dyn_vprintf(s, fmt, ap);

  if(!rc)
    return CURLE_OK;
  else if(rc == MERR_TOO_LARGE)
    return CURLE_TOO_LARGE;
  return CURLE_OUT_OF_MEMORY;
#else
  char *str;
  str = vaprintf(fmt, ap); /* this allocs a new string to append */

  if(str) {
    CURLcode result = dyn_nappend(s, (unsigned char *)str, strlen(str));
    free(str);
    return result;
  }
  /* If we failed, we cleanup the whole buffer and return error */
  Curl_dyn_free(s);
  return CURLE_OUT_OF_MEMORY;
#endif
}


/*
 * Append a null-terminated string at the end.
 */
CURLcode Curl_dyn_add(struct dynbuf *s, const char *str)
{
  size_t n;
  DEBUGASSERT(str);
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  n = strlen(str);
  return dyn_nappend(s, (unsigned char *)str, n);
}

/*
 * Clears the string, keeps the allocation. This can also be called on a
 * buffer that already was freed.
 */
void Curl_dyn_reset(struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  if(s->leng)
    s->bufr[0] = 0;
  s->leng = 0;
}

/*
 * Append a string printf()-style
 */
CURLcode Curl_dyn_addf(struct dynbuf *s, const char *fmt, ...)
{
  CURLcode result;
  va_list ap;
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  va_start(ap, fmt);
  result = Curl_dyn_vaddf(s, fmt, ap);
  va_end(ap);
  return result;
}

/* fputc() look-alike */
static int alloc_addbyter(unsigned char outc, void *f)
{
  struct asprintf *infop = f;
  CURLcode result = Curl_dyn_addn(infop->b, &outc, 1);
  if(result) {
    infop->merr = result == CURLE_TOO_LARGE ? MERR_TOO_LARGE : MERR_MEM;
    return 1 ; /* fail */
  }
  return 0;
}

/* fputc() look-alike */
static int addbyter(unsigned char outc, void *f)
{
  struct nsprintf *infop = f;
  if(infop->length < infop->max) {
    /* only do this if we have not reached max length yet */
    *infop->buffer++ = (char)outc; /* store */
    infop->length++; /* we are now one byte larger */
    return 0;     /* fputc() returns like this on success */
  }
  return 1;
}

static int formatf(void *userp, int (*stream)(unsigned char, void *), const char *format, va_list ap_save);
char *curl_mvaprintf(const char *format, va_list ap_save)
{
  struct asprintf info;
  struct dynbuf dyn;
  info.b = &dyn;
  Curl_dyn_init(info.b, DYN_APRINTF);
  info.merr = MERR_OK;

  (void)formatf(&info, alloc_addbyter, format, ap_save);
  if(info.merr) {
    Curl_dyn_free(info.b);
    return NULL;
  }
  if(Curl_dyn_len(info.b))
    return Curl_dyn_ptr(info.b);
  return strdup("");
}

char *curl_maprintf(const char *format, ...)
{
  va_list ap_save;
  char *s;
  va_start(ap_save, format);
  s = curl_mvaprintf(format, ap_save);
  va_end(ap_save);
  return s;
}

/* Mapping table to go from lowercase to uppercase for plain ASCII.*/
static const unsigned char touppermap[256] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 65,
66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* Mapping table to go from uppercase to lowercase for plain ASCII.*/
static const unsigned char tolowermap[256] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
62, 63, 64, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91, 92, 93, 94, 95,
96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* Portable, consistent tolower. Do not use tolower() because its behavior is
   altered by the current locale. */
char Curl_raw_tolower(char in)
{
  return (char)tolowermap[(unsigned char) in];
}

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...);
static int parsefmt(const char *format,
                    struct outsegment *out,
                    struct va_input *in,
                    int *opieces,
                    int *ipieces, va_list arglist)
{
  char *fmt = (char *)format;
  int param_num = 0;
  int param;
  int width;
  int precision;
  unsigned int flags;
  FormatType type;
  int max_param = -1;
  int i;
  int ocount = 0;
  unsigned char usedinput[MAX_PARAMETERS/8];
  size_t outlen = 0;
  struct outsegment *optr;
  int use_dollar = DOLLAR_UNKNOWN;
  char *start = fmt;

  /* clear, set a bit for each used input */
  memset(usedinput, 0, sizeof(usedinput));

  while(*fmt) {
    if(*fmt == '%') {
      struct va_input *iptr;
      bool loopit = TRUE;
      fmt++;
      outlen = (size_t)(fmt - start - 1);
      if(*fmt == '%') {
        /* this means a %% that should be output only as %. Create an output
           segment. */
        if(outlen) {
          optr = &out[ocount++];
          if(ocount > MAX_SEGMENTS)
            return PFMT_MANYSEGS;
          optr->input = 0;
          optr->flags = FLAGS_SUBSTR;
          optr->start = start;
          optr->outlen = outlen;
        }
        start = fmt;
        fmt++;
        continue; /* while */
      }

      flags = 0;
      width = precision = 0;

      if(use_dollar != DOLLAR_NOPE) {
        param = dollarstring(fmt, &fmt);
        if(param < 0) {
          if(use_dollar == DOLLAR_USE)
            /* illegal combo */
            return PFMT_DOLLAR;

          /* we got no positional, just get the next arg */
          param = -1;
          use_dollar = DOLLAR_NOPE;
        }
        else
          use_dollar = DOLLAR_USE;
      }
      else
        param = -1;

      /* Handle the flags */
      while(loopit) {
        switch(*fmt++) {
        case ' ':
          flags |= FLAGS_SPACE;
          break;
        case '+':
          flags |= FLAGS_SHOWSIGN;
          break;
        case '-':
          flags |= FLAGS_LEFT;
          flags &= ~(unsigned int)FLAGS_PAD_NIL;
          break;
        case '#':
          flags |= FLAGS_ALT;
          break;
        case '.':
          if('*' == *fmt) {
            /* The precision is picked from a specified parameter */
            flags |= FLAGS_PRECPARAM;
            fmt++;

            if(use_dollar == DOLLAR_USE) {
              precision = dollarstring(fmt, &fmt);
              if(precision < 0)
                /* illegal combo */
                return PFMT_DOLLARPREC;
            }
            else
              /* get it from the next argument */
              precision = -1;
          }
          else {
            bool is_neg = FALSE;
            flags |= FLAGS_PREC;
            precision = 0;
            if('-' == *fmt) {
              is_neg = TRUE;
              fmt++;
            }
            while(ISDIGIT(*fmt)) {
              if(precision > INT_MAX/10)
                return PFMT_PREC;
              precision *= 10;
              precision += *fmt - '0';
              fmt++;
            }
            if(is_neg)
              precision = -precision;
          }
          if((flags & (FLAGS_PREC | FLAGS_PRECPARAM)) ==
             (FLAGS_PREC | FLAGS_PRECPARAM))
            /* it is not permitted to use both kinds of precision for the same
               argument */
            return PFMT_PRECMIX;
          break;
        case 'h':
          flags |= FLAGS_SHORT;
          break;
#if defined(_WIN32) || defined(_WIN32_WCE)
        case 'I':
          /* Non-ANSI integer extensions I32 I64 */
          if((fmt[0] == '3') && (fmt[1] == '2')) {
            flags |= FLAGS_LONG;
            fmt += 2;
          }
          else if((fmt[0] == '6') && (fmt[1] == '4')) {
            flags |= FLAGS_LONGLONG;
            fmt += 2;
          }
          else {
#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
            flags |= FLAGS_LONGLONG;
#else
            flags |= FLAGS_LONG;
#endif
          }
          break;
#endif /* _WIN32 || _WIN32_WCE */
        case 'l':
          if(flags & FLAGS_LONG)
            flags |= FLAGS_LONGLONG;
          else
            flags |= FLAGS_LONG;
          break;
        case 'L':
          flags |= FLAGS_LONGDOUBLE;
          break;
        case 'q':
          flags |= FLAGS_LONGLONG;
          break;
        case 'z':
          /* the code below generates a warning if -Wunreachable-code is
             used */
#if (SIZEOF_SIZE_T > SIZEOF_LONG)
          flags |= FLAGS_LONGLONG;
#else
          flags |= FLAGS_LONG;
#endif
          break;
        case 'O':
#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
          flags |= FLAGS_LONGLONG;
#else
          flags |= FLAGS_LONG;
#endif
          break;
        case '0':
          if(!(flags & FLAGS_LEFT))
            flags |= FLAGS_PAD_NIL;
          FALLTHROUGH();
        case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
          flags |= FLAGS_WIDTH;
          width = 0;
          fmt--;
          do {
            if(width > INT_MAX/10)
              return PFMT_WIDTH;
            width *= 10;
            width += *fmt - '0';
            fmt++;
          } while(ISDIGIT(*fmt));
          break;
        case '*':  /* read width from argument list */
          flags |= FLAGS_WIDTHPARAM;
          if(use_dollar == DOLLAR_USE) {
            width = dollarstring(fmt, &fmt);
            if(width < 0)
              /* illegal combo */
              return PFMT_DOLLARWIDTH;
          }
          else
            /* pick from the next argument */
            width = -1;
          break;
        default:
          loopit = FALSE;
          fmt--;
          break;
        } /* switch */
      } /* while */

      switch(*fmt) {
      case 'S':
        flags |= FLAGS_ALT;
        FALLTHROUGH();
      case 's':
        type = FORMAT_STRING;
        break;
      case 'n':
        type = FORMAT_INTPTR;
        break;
      case 'p':
        type = FORMAT_PTR;
        break;
      case 'd':
      case 'i':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONG;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONG;
        else
          type = FORMAT_INT;
        break;
      case 'u':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONGU;
        else
          type = FORMAT_INTU;
        flags |= FLAGS_UNSIGNED;
        break;
      case 'o':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONGU;
        else
          type = FORMAT_INTU;
        flags |= FLAGS_OCTAL|FLAGS_UNSIGNED;
        break;
      case 'x':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONGU;
        else
          type = FORMAT_INTU;
        flags |= FLAGS_HEX|FLAGS_UNSIGNED;
        break;
      case 'X':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONGU;
        else
          type = FORMAT_INTU;
        flags |= FLAGS_HEX|FLAGS_UPPER|FLAGS_UNSIGNED;
        break;
      case 'c':
        type = FORMAT_INT;
        flags |= FLAGS_CHAR;
        break;
      case 'f':
        type = FORMAT_DOUBLE;
        break;
      case 'e':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATE;
        break;
      case 'E':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATE|FLAGS_UPPER;
        break;
      case 'g':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATG;
        break;
      case 'G':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATG|FLAGS_UPPER;
        break;
      default:
        /* invalid instruction, disregard and continue */
        continue;
      } /* switch */

      if(flags & FLAGS_WIDTHPARAM) {
        if(width < 0)
          width = param_num++;
        else {
          /* if this identifies a parameter already used, this
             is illegal */
          if(usedinput[width/8] & (1 << (width&7)))
            return PFMT_WIDTHARG;
        }
        if(width >= MAX_PARAMETERS)
          return PFMT_MANYARGS;
        if(width >= max_param)
          max_param = width;

        in[width].type = FORMAT_WIDTH;
        /* mark as used */
        usedinput[width/8] |= (unsigned char)(1 << (width&7));
      }

      if(flags & FLAGS_PRECPARAM) {
        if(precision < 0)
          precision = param_num++;
        else {
          /* if this identifies a parameter already used, this
             is illegal */
          if(usedinput[precision/8] & (1 << (precision&7)))
            return PFMT_PRECARG;
        }
        if(precision >= MAX_PARAMETERS)
          return PFMT_MANYARGS;
        if(precision >= max_param)
          max_param = precision;

        in[precision].type = FORMAT_PRECISION;
        usedinput[precision/8] |= (unsigned char)(1 << (precision&7));
      }

      /* Handle the specifier */
      if(param < 0)
        param = param_num++;
      if(param >= MAX_PARAMETERS)
        return PFMT_MANYARGS;
      if(param >= max_param)
        max_param = param;

      iptr = &in[param];
      iptr->type = type;

      /* mark this input as used */
      usedinput[param/8] |= (unsigned char)(1 << (param&7));

      fmt++;
      optr = &out[ocount++];
      if(ocount > MAX_SEGMENTS)
        return PFMT_MANYSEGS;
      optr->input = (unsigned int)param;
      optr->flags = flags;
      optr->width = width;
      optr->precision = precision;
      optr->start = start;
      optr->outlen = outlen;
      start = fmt;
    }
    else
      fmt++;
  }

  /* is there a trailing piece */
  outlen = (size_t)(fmt - start);
  if(outlen) {
    optr = &out[ocount++];
    if(ocount > MAX_SEGMENTS)
      return PFMT_MANYSEGS;
    optr->input = 0;
    optr->flags = FLAGS_SUBSTR;
    optr->start = start;
    optr->outlen = outlen;
  }

  /* Read the arg list parameters into our data list */
  for(i = 0; i < max_param + 1; i++) {
    struct va_input *iptr = &in[i];
    if(!(usedinput[i/8] & (1 << (i&7))))
      /* bad input */
      return PFMT_INPUTGAP;

    /* based on the type, read the correct argument */
    switch(iptr->type) {
    case FORMAT_STRING:
      iptr->val.str = va_arg(arglist, char *);
      break;

    case FORMAT_INTPTR:
    case FORMAT_PTR:
      iptr->val.ptr = va_arg(arglist, void *);
      break;

    case FORMAT_LONGLONGU:
      iptr->val.numu = (mp_uintmax_t)va_arg(arglist, mp_uintmax_t);
      break;

    case FORMAT_LONGLONG:
      iptr->val.nums = (mp_intmax_t)va_arg(arglist, mp_intmax_t);
      break;

    case FORMAT_LONGU:
      iptr->val.numu = (mp_uintmax_t)va_arg(arglist, unsigned long);
      break;

    case FORMAT_LONG:
      iptr->val.nums = (mp_intmax_t)va_arg(arglist, long);
      break;

    case FORMAT_INTU:
      iptr->val.numu = (mp_uintmax_t)va_arg(arglist, unsigned int);
      break;

    case FORMAT_INT:
    case FORMAT_WIDTH:
    case FORMAT_PRECISION:
      iptr->val.nums = (mp_intmax_t)va_arg(arglist, int);
      break;

    case FORMAT_DOUBLE:
      iptr->val.dnum = va_arg(arglist, double);
      break;

    default:
      DEBUGASSERT(NULL); /* unexpected */
      break;
    }
  }
  *ipieces = max_param + 1;
  *opieces = ocount;

  return PFMT_OK;
}

/*
 * formatf() - the general printf function.
 *
 * It calls parsefmt() to parse the format string. It populates two arrays;
 * one that describes the input arguments and one that describes a number of
 * output segments.
 *
 * On success, the input array describes the type of all arguments and their
 * values.
 *
 * The function then iterates over the output segments and outputs them one
 * by one until done. Using the appropriate input arguments (if any).
 *
 * All output is sent to the 'stream()' callback, one byte at a time.
 */

static int formatf(
  void *userp, /* untouched by format(), just sent to the stream() function in
                  the second argument */
  /* function pointer called for each output character */
  int (*stream)(unsigned char, void *),
  const char *format,    /* %-formatted string */
  va_list ap_save) /* list of parameters */
{
  static const char nilstr[] = "(nil)";
  const char *digits = lower_digits;   /* Base-36 digits for numbers.  */
  int done = 0;   /* number of characters written  */
  int i;
  int ocount = 0; /* number of output segments */
  int icount = 0; /* number of input arguments */

  struct outsegment output[MAX_SEGMENTS];
  struct va_input input[MAX_PARAMETERS];
  char work[BUFFSIZE];

  /* 'workend' points to the final buffer byte position, but with an extra
     byte as margin to avoid the (FALSE?) warning Coverity gives us
     otherwise */
  char *workend = &work[sizeof(work) - 2];

  /* Parse the format string */
  if(parsefmt(format, output, input, &ocount, &icount, ap_save))
    return 0;

  for(i = 0; i < ocount; i++) {
    struct outsegment *optr = &output[i];
    struct va_input *iptr;
    bool is_alt;            /* Format spec modifiers.  */
    int width;              /* Width of a field.  */
    int prec;               /* Precision of a field.  */
    bool is_neg;            /* Decimal integer is negative.  */
    unsigned long base;     /* Base of a number to be written.  */
    mp_uintmax_t num;       /* Integral values to be written.  */
    mp_intmax_t signed_num; /* Used to convert negative in positive.  */
    char *w;
    size_t outlen = optr->outlen;
    unsigned int flags = optr->flags;

    if(outlen) {
      char *str = optr->start;
      for(; outlen && *str; outlen--)
        OUTCHAR(*str++);
      if(optr->flags & FLAGS_SUBSTR)
        /* this is just a substring */
        continue;
    }

    /* pick up the specified width */
    if(flags & FLAGS_WIDTHPARAM) {
      width = (int)input[optr->width].val.nums;
      if(width < 0) {
        /* "A negative field width is taken as a '-' flag followed by a
           positive field width." */
        if(width == INT_MIN)
          width = INT_MAX;
        else
          width = -width;
        flags |= FLAGS_LEFT;
        flags &= ~(unsigned int)FLAGS_PAD_NIL;
      }
    }
    else
      width = optr->width;

    /* pick up the specified precision */
    if(flags & FLAGS_PRECPARAM) {
      prec = (int)input[optr->precision].val.nums;
      if(prec < 0)
        /* "A negative precision is taken as if the precision were
           omitted." */
        prec = -1;
    }
    else if(flags & FLAGS_PREC)
      prec = optr->precision;
    else
      prec = -1;

    is_alt = (flags & FLAGS_ALT) ? 1 : 0;
    iptr = &input[optr->input];

    switch(iptr->type) {
    case FORMAT_INTU:
    case FORMAT_LONGU:
    case FORMAT_LONGLONGU:
      flags |= FLAGS_UNSIGNED;
      FALLTHROUGH();
    case FORMAT_INT:
    case FORMAT_LONG:
    case FORMAT_LONGLONG:
      num = iptr->val.numu;
      if(flags & FLAGS_CHAR) {
        /* Character.  */
        if(!(flags & FLAGS_LEFT))
          while(--width > 0)
            OUTCHAR(' ');
        OUTCHAR((char) num);
        if(flags & FLAGS_LEFT)
          while(--width > 0)
            OUTCHAR(' ');
        break;
      }
      if(flags & FLAGS_OCTAL) {
        /* Octal unsigned integer */
        base = 8;
        is_neg = FALSE;
      }
      else if(flags & FLAGS_HEX) {
        /* Hexadecimal unsigned integer */
        digits = (flags & FLAGS_UPPER) ? upper_digits : lower_digits;
        base = 16;
        is_neg = FALSE;
      }
      else if(flags & FLAGS_UNSIGNED) {
        /* Decimal unsigned integer */
        base = 10;
        is_neg = FALSE;
      }
      else {
        /* Decimal integer.  */
        base = 10;

        is_neg = (iptr->val.nums < (mp_intmax_t)0);
        if(is_neg) {
          /* signed_num might fail to hold absolute negative minimum by 1 */
          signed_num = iptr->val.nums + (mp_intmax_t)1;
          signed_num = -signed_num;
          num = (mp_uintmax_t)signed_num;
          num += (mp_uintmax_t)1;
        }
      }
number:
      /* Supply a default precision if none was given.  */
      if(prec == -1)
        prec = 1;

      /* Put the number in WORK.  */
      w = workend;
      switch(base) {
      case 10:
        while(num > 0) {
          *w-- = (char)('0' + (num % 10));
          num /= 10;
        }
        break;
      default:
        while(num > 0) {
          *w-- = digits[num % base];
          num /= base;
        }
        break;
      }
      width -= (int)(workend - w);
      prec -= (int)(workend - w);

      if(is_alt && base == 8 && prec <= 0) {
        *w-- = '0';
        --width;
      }

      if(prec > 0) {
        width -= prec;
        while(prec-- > 0 && w >= work)
          *w-- = '0';
      }

      if(is_alt && base == 16)
        width -= 2;

      if(is_neg || (flags & FLAGS_SHOWSIGN) || (flags & FLAGS_SPACE))
        --width;

      if(!(flags & FLAGS_LEFT) && !(flags & FLAGS_PAD_NIL))
        while(width-- > 0)
          OUTCHAR(' ');

      if(is_neg)
        OUTCHAR('-');
      else if(flags & FLAGS_SHOWSIGN)
        OUTCHAR('+');
      else if(flags & FLAGS_SPACE)
        OUTCHAR(' ');

      if(is_alt && base == 16) {
        OUTCHAR('0');
        if(flags & FLAGS_UPPER)
          OUTCHAR('X');
        else
          OUTCHAR('x');
      }

      if(!(flags & FLAGS_LEFT) && (flags & FLAGS_PAD_NIL))
        while(width-- > 0)
          OUTCHAR('0');

      /* Write the number.  */
      while(++w <= workend) {
        OUTCHAR(*w);
      }

      if(flags & FLAGS_LEFT)
        while(width-- > 0)
          OUTCHAR(' ');
      break;

    case FORMAT_STRING: {
      const char *str;
      size_t len;

      str = (char *)iptr->val.str;
      if(!str) {
        /* Write null string if there is space.  */
        if(prec == -1 || prec >= (int) sizeof(nilstr) - 1) {
          str = nilstr;
          len = sizeof(nilstr) - 1;
          /* Disable quotes around (nil) */
          flags &= ~(unsigned int)FLAGS_ALT;
        }
        else {
          str = "";
          len = 0;
        }
      }
      else if(prec != -1)
        len = (size_t)prec;
      else if(*str == '\0')
        len = 0;
      else
        len = strlen(str);

      width -= (len > INT_MAX) ? INT_MAX : (int)len;

      if(flags & FLAGS_ALT)
        OUTCHAR('"');

      if(!(flags & FLAGS_LEFT))
        while(width-- > 0)
          OUTCHAR(' ');

      for(; len && *str; len--)
        OUTCHAR(*str++);
      if(flags & FLAGS_LEFT)
        while(width-- > 0)
          OUTCHAR(' ');

      if(flags & FLAGS_ALT)
        OUTCHAR('"');
      break;
    }

    case FORMAT_PTR:
      /* Generic pointer.  */
      if(iptr->val.ptr) {
        /* If the pointer is not NULL, write it as a %#x spec.  */
        base = 16;
        digits = (flags & FLAGS_UPPER) ? upper_digits : lower_digits;
        is_alt = TRUE;
        num = (size_t) iptr->val.ptr;
        is_neg = FALSE;
        goto number;
      }
      else {
        /* Write "(nil)" for a nil pointer.  */
        const char *point;

        width -= (int)(sizeof(nilstr) - 1);
        if(flags & FLAGS_LEFT)
          while(width-- > 0)
            OUTCHAR(' ');
        for(point = nilstr; *point != '\0'; ++point)
          OUTCHAR(*point);
        if(!(flags & FLAGS_LEFT))
          while(width-- > 0)
            OUTCHAR(' ');
      }
      break;

    case FORMAT_DOUBLE: {
      char formatbuf[32]="%";
      char *fptr = &formatbuf[1];
      size_t left = sizeof(formatbuf)-strlen(formatbuf);
      int len;

      if(flags & FLAGS_WIDTH)
        width = optr->width;

      if(flags & FLAGS_PREC)
        prec = optr->precision;

      if(flags & FLAGS_LEFT)
        *fptr++ = '-';
      if(flags & FLAGS_SHOWSIGN)
        *fptr++ = '+';
      if(flags & FLAGS_SPACE)
        *fptr++ = ' ';
      if(flags & FLAGS_ALT)
        *fptr++ = '#';

      *fptr = 0;

      if(width >= 0) {
        size_t dlen;
        if(width >= (int)sizeof(work))
          width = sizeof(work)-1;
        /* RECURSIVE USAGE */
        dlen = (size_t)curl_msnprintf(fptr, left, "%d", width);
        fptr += dlen;
        left -= dlen;
      }
      if(prec >= 0) {
        /* for each digit in the integer part, we can have one less
           precision */
        size_t maxprec = sizeof(work) - 2;
        double val = iptr->val.dnum;
        if(width > 0 && prec <= width)
          maxprec -= (size_t)width;
        while(val >= 10.0) {
          val /= 10;
          maxprec--;
        }

        if(prec > (int)maxprec)
          prec = (int)maxprec-1;
        if(prec < 0)
          prec = 0;
        /* RECURSIVE USAGE */
        len = curl_msnprintf(fptr, left, ".%d", prec);
        fptr += len;
      }
      if(flags & FLAGS_LONG)
        *fptr++ = 'l';

      if(flags & FLAGS_FLOATE)
        *fptr++ = (char)((flags & FLAGS_UPPER) ? 'E' : 'e');
      else if(flags & FLAGS_FLOATG)
        *fptr++ = (char)((flags & FLAGS_UPPER) ? 'G' : 'g');
      else
        *fptr++ = 'f';

      *fptr = 0; /* and a final null-termination */

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
      /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
         output characters */
#ifdef HAVE_SNPRINTF
      (snprintf)(work, sizeof(work), formatbuf, iptr->val.dnum);
#else
      (sprintf)(work, formatbuf, iptr->val.dnum);
#endif
#ifdef __clang__
#pragma clang diagnostic pop
#endif
      DEBUGASSERT(strlen(work) <= sizeof(work));
      for(fptr = work; *fptr; fptr++)
        OUTCHAR(*fptr);
      break;
    }

    case FORMAT_INTPTR:
      /* Answer the count of characters written.  */
#ifdef HAVE_LONG_LONG_TYPE
      if(flags & FLAGS_LONGLONG)
        *(LONG_LONG_TYPE *) iptr->val.ptr = (LONG_LONG_TYPE)done;
      else
#endif
        if(flags & FLAGS_LONG)
          *(long *) iptr->val.ptr = (long)done;
      else if(!(flags & FLAGS_SHORT))
        *(int *) iptr->val.ptr = (int)done;
      else
        *(short *) iptr->val.ptr = (short)done;
      break;

    default:
      break;
    }
  }
  return done;
}

int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format,
                    va_list ap_save)
{
  int retcode;
  struct nsprintf info;

  info.buffer = buffer;
  info.length = 0;
  info.max = maxlength;

  retcode = formatf(&info, addbyter, format, ap_save);
  if(info.max) {
    /* we terminate this with a zero byte */
    if(info.max == info.length) {
      /* we are at maximum, scrap the last letter */
      info.buffer[-1] = 0;
      DEBUGASSERT(retcode);
      retcode--; /* do not count the nul byte */
    }
    else
      info.buffer[0] = 0;
  }
  return retcode;
}

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = curl_mvsnprintf(buffer, maxlength, format, ap_save);
  va_end(ap_save);
  return retcode;
}

/*
 * Helpers for IDNA conversions.
 */
bool Curl_is_ASCII_name(const char *hostname)
{
  /* get an UNSIGNED local version of the pointer */
  const unsigned char *ch = (const unsigned char *)hostname;

  if(!hostname) /* bad input, consider it ASCII! */
    return TRUE;

  while(*ch) {
    if(*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}

/*
 * Curl_urldecode() URL decodes the given string.
 *
 * Returns a pointer to a malloced string in *ostring with length given in
 * *olen. If length == 0, the length is assumed to be strlen(string).
 *
 * ctrl options:
 * - REJECT_NADA: accept everything
 * - REJECT_CTRL: rejects control characters (byte codes lower than 32) in
 *                the data
 * - REJECT_ZERO: rejects decoded zero bytes
 *
 * The values for the enum starts at 2, to make the assert detect legacy
 * invokes that used TRUE/FALSE (0 and 1).
 */

CURLcode Curl_urldecode(const char *string, size_t length,
                        char **ostring, size_t *olen,
                        enum urlreject ctrl)
{
  size_t alloc;
  char *ns;

  DEBUGASSERT(string);
  DEBUGASSERT(ctrl >= REJECT_NADA); /* crash on TRUE/FALSE */

  alloc = (length ? length : strlen(string));
  ns = malloc(alloc + 1);

  if(!ns)
    return CURLE_OUT_OF_MEMORY;

  /* store output string */
  *ostring = ns;

  while(alloc) {
    unsigned char in = (unsigned char)*string;
    if(('%' == in) && (alloc > 2) &&
       ISXDIGIT(string[1]) && ISXDIGIT(string[2])) {
      /* this is two hexadecimal digits following a '%' */
      in = (unsigned char)(onehex2dec(string[1]) << 4) | onehex2dec(string[2]);

      string += 3;
      alloc -= 3;
    }
    else {
      string++;
      alloc--;
    }

    if(((ctrl == REJECT_CTRL) && (in < 0x20)) ||
       ((ctrl == REJECT_ZERO) && (in == 0))) {
      Curl_safefree(*ostring);
      return CURLE_URL_MALFORMAT;
    }

    *ns++ = (char)in;
  }
  *ns = 0; /* terminate it */

  if(olen)
    /* store output size */
    *olen = ns - *ostring;

  return CURLE_OK;
}

/***************************************************************************
 *
 * Curl_memdup0(source, length)
 *
 * Copies the 'source' string to a newly allocated buffer (that is returned).
 * Copies 'length' bytes then adds a null terminator.
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
void *Curl_memdup0(const char *src, size_t length)
{
  char *buf = malloc(length + 1);
  if(!buf)
    return NULL;
  memcpy(buf, src, length);
  buf[length] = 0;
  return buf;
}

/*
 * Find the separator at the end of the hostname, or the '?' in cases like
 * http://www.example.com?id=2380
 */
static const char *find_host_sep(const char *url)
{
  const char *sep;
  const char *query;

  /* Find the start of the hostname */
  sep = strstr(url, "//");
  if(!sep)
    sep = url;
  else
    sep += 2;

  query = strchr(sep, '?');
  sep = strchr(sep, '/');

  if(!sep)
    sep = url + strlen(url);

  if(!query)
    query = url + strlen(url);

  return sep < query ? sep : query;
}

/* urlencode_str() writes data into an output dynbuf and URL-encodes the
 * spaces in the source URL accordingly.
 *
 * URL encoding should be skipped for hostnames, otherwise IDN resolution
 * will fail.
 */
static CURLUcode urlencode_str(struct dynbuf *o, const char *url,
                               size_t len, bool relative,
                               bool query)
{
  /* we must add this with whitespace-replacing */
  bool left = !query;
  const unsigned char *iptr;
  const unsigned char *host_sep = (const unsigned char *) url;
  CURLcode result;

  if(!relative)
    host_sep = (const unsigned char *) find_host_sep(url);

  for(iptr = (unsigned char *)url;    /* read from here */
      len; iptr++, len--) {

    if(iptr < host_sep) {
      result = Curl_dyn_addn(o, iptr, 1);
      if(result)
        return cc2cu(result);
      continue;
    }

    if(*iptr == ' ') {
      if(left)
        result = Curl_dyn_addn(o, "%20", 3);
      else
        result = Curl_dyn_addn(o, "+", 1);
      if(result)
        return cc2cu(result);
      continue;
    }

    if(*iptr == '?')
      left = FALSE;

    if(urlchar_needs_escaping(*iptr)) {
      char out[3]={'%'};
      out[1] = hexdigits[*iptr >> 4];
      out[2] = hexdigits[*iptr & 0xf];
      result = Curl_dyn_addn(o, out, 3);
    }
    else
      result = Curl_dyn_addn(o, iptr, 1);
    if(result)
      return cc2cu(result);
  }

  return CURLUE_OK;
}

/* returns the handler if the given scheme is built-in */
const struct Curl_handler *Curl_getn_scheme_handler(const char *scheme,
                                                    size_t len)
{
  /* table generated by schemetable.c:
     1. gcc schemetable.c && ./a.out
     2. check how small the table gets
     3. tweak the hash algorithm, then rerun from 1
     4. when the table is good enough
     5. copy the table into this source code
     6. make sure this function uses the same hash function that worked for
     schemetable.c
     7. if needed, adjust the #ifdefs in schemetable.c and rerun
     */
  static const struct Curl_handler * const protocols[67] = {
    &Curl_handler_file, NULL, NULL, &Curl_handler_gophers, NULL,
    &Curl_handler_rtmpe, &Curl_handler_smtp, &Curl_handler_sftp, &Curl_handler_smb, &Curl_handler_smtps,
    &Curl_handler_telnet, &Curl_handler_gopher, &Curl_handler_tftp, NULL, NULL,
    NULL, &Curl_handler_ftps, &Curl_handler_http, &Curl_handler_imap, &Curl_handler_rtmps,
    &Curl_handler_rtmpt, NULL, NULL, NULL, &Curl_handler_ldaps,
    &Curl_handler_wss, &Curl_handler_https, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    &Curl_handler_rtsp, &Curl_handler_smbs, &Curl_handler_scp, NULL, NULL,
    NULL, &Curl_handler_pop3, NULL, NULL, &Curl_handler_rtmp,
    NULL, NULL, NULL, &Curl_handler_rtmpte, NULL,
    NULL, NULL, &Curl_handler_dict, NULL, NULL,
    NULL, &Curl_handler_mqtt, &Curl_handler_pop3s, &Curl_handler_imaps, NULL,
    &Curl_handler_ws, NULL, &Curl_handler_rtmpts, &Curl_handler_ldap, NULL,
    NULL, &Curl_handler_ftp,
  };

  if(len && (len <= 7)) {
    const char *s = scheme;
    size_t l = len;
    const struct Curl_handler *h;
    unsigned int c = 978;
    while(l) {
      c <<= 5;
      c += (unsigned int)Curl_raw_tolower(*s);
      s++;
      l--;
    }

    h = protocols[c % 67];
    if(h && strncasecompare(scheme, h->scheme, len) && !h->scheme[len])
      return h;
  }
  return NULL;
}
	
const struct Curl_handler *Curl_get_scheme_handler(const char *scheme)
{
  return Curl_getn_scheme_handler(scheme, strlen(scheme));
}

CURLUcode curl_url_get(const CURLU *u, CURLUPart what,
                       char **part, unsigned int flags)
{
  const char *ptr;
  CURLUcode ifmissing = CURLUE_UNKNOWN_PART;
  char portbuf[7];
  bool urldecode = (flags & CURLU_URLDECODE) ? 1 : 0;
  bool urlencode = (flags & CURLU_URLENCODE) ? 1 : 0;
  bool punycode = FALSE;
  bool depunyfy = FALSE;
  bool plusdecode = FALSE;
  (void)flags;
  if(!u)
    return CURLUE_BAD_HANDLE;
  if(!part)
    return CURLUE_BAD_PARTPOINTER;
  *part = NULL;

  switch(what) {
  case CURLUPART_SCHEME:
    ptr = u->scheme;
    ifmissing = CURLUE_NO_SCHEME;
    urldecode = FALSE; /* never for schemes */
    if((flags & CURLU_NO_GUESS_SCHEME) && u->guessed_scheme)
      return CURLUE_NO_SCHEME;
    break;
  case CURLUPART_USER:
    ptr = u->user;
    ifmissing = CURLUE_NO_USER;
    break;
  case CURLUPART_PASSWORD:
    ptr = u->password;
    ifmissing = CURLUE_NO_PASSWORD;
    break;
  case CURLUPART_OPTIONS:
    ptr = u->options;
    ifmissing = CURLUE_NO_OPTIONS;
    break;
  case CURLUPART_HOST:
    ptr = u->host;
    ifmissing = CURLUE_NO_HOST;
    punycode = (flags & CURLU_PUNYCODE) ? 1 : 0;
    depunyfy = (flags & CURLU_PUNY2IDN) ? 1 : 0;
    break;
  case CURLUPART_ZONEID:
    ptr = u->zoneid;
    ifmissing = CURLUE_NO_ZONEID;
    break;
  case CURLUPART_PORT:
    ptr = u->port;
    ifmissing = CURLUE_NO_PORT;
    urldecode = FALSE; /* never for port */
    if(!ptr && (flags & CURLU_DEFAULT_PORT) && u->scheme) {
      /* there is no stored port number, but asked to deliver
         a default one for the scheme */
      const struct Curl_handler *h = Curl_get_scheme_handler(u->scheme);
      if(h) {
        msnprintf(portbuf, sizeof(portbuf), "%u", h->defport);
        ptr = portbuf;
      }
    }
    else if(ptr && u->scheme) {
      /* there is a stored port number, but ask to inhibit if
         it matches the default one for the scheme */
      const struct Curl_handler *h = Curl_get_scheme_handler(u->scheme);
      if(h && (h->defport == u->portnum) &&
         (flags & CURLU_NO_DEFAULT_PORT))
        ptr = NULL;
    }
    break;
  case CURLUPART_PATH:
    ptr = u->path;
    if(!ptr)
      ptr = "/";
    break;
  case CURLUPART_QUERY:
    ptr = u->query;
    ifmissing = CURLUE_NO_QUERY;
    plusdecode = urldecode;
    if(ptr && !ptr[0] && !(flags & CURLU_GET_EMPTY))
      /* there was a blank query and the user do not ask for it */
      ptr = NULL;
    break;
  case CURLUPART_FRAGMENT:
    ptr = u->fragment;
    ifmissing = CURLUE_NO_FRAGMENT;
    if(!ptr && u->fragment_present && flags & CURLU_GET_EMPTY)
      /* there was a blank fragment and the user asks for it */
      ptr = "";
    break;
  case CURLUPART_URL: {
    char *url;
    char *scheme;
    char *options = u->options;
    char *port = u->port;
    char *allochost = NULL;
    bool show_fragment =
      u->fragment || (u->fragment_present && flags & CURLU_GET_EMPTY);
    bool show_query =
      (u->query && u->query[0]) ||
      (u->query_present && flags & CURLU_GET_EMPTY);
    punycode = (flags & CURLU_PUNYCODE) ? 1 : 0;
    depunyfy = (flags & CURLU_PUNY2IDN) ? 1 : 0;
    if(u->scheme && strcasecompare("file", u->scheme)) {
      url = aprintf("file://%s%s%s",
                    u->path,
                    show_fragment ? "#": "",
                    u->fragment ? u->fragment : "");
    }
    else if(!u->host)
      return CURLUE_NO_HOST;
    else {
      const struct Curl_handler *h = NULL;
      char schemebuf[MAX_SCHEME_LEN + 5];
      if(u->scheme)
        scheme = u->scheme;
      else if(flags & CURLU_DEFAULT_SCHEME)
        scheme = (char *) DEFAULT_SCHEME;
      else
        return CURLUE_NO_SCHEME;

      h = Curl_get_scheme_handler(scheme);
      if(!port && (flags & CURLU_DEFAULT_PORT)) {
        /* there is no stored port number, but asked to deliver
           a default one for the scheme */
        if(h) {
          msnprintf(portbuf, sizeof(portbuf), "%u", h->defport);
          port = portbuf;
        }
      }
      else if(port) {
        /* there is a stored port number, but asked to inhibit if it matches
           the default one for the scheme */
        if(h && (h->defport == u->portnum) &&
           (flags & CURLU_NO_DEFAULT_PORT))
          port = NULL;
      }

      if(h && !(h->flags & PROTOPT_URLOPTIONS))
        options = NULL;

      if(u->host[0] == '[') {
        if(u->zoneid) {
          /* make it '[ host %25 zoneid ]' */
          struct dynbuf enc;
          size_t hostlen = strlen(u->host);
          Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
          if(Curl_dyn_addf(&enc, "%.*s%%25%s]", (int)hostlen - 1, u->host,
                           u->zoneid))
            return CURLUE_OUT_OF_MEMORY;
          allochost = Curl_dyn_ptr(&enc);
        }
      }
      else if(urlencode) {
        allochost = curl_easy_escape(NULL, u->host, 0);
        if(!allochost)
          return CURLUE_OUT_OF_MEMORY;
      }
      else if(punycode) {
        if(!Curl_is_ASCII_name(u->host)) {
#ifndef USE_IDN
          return CURLUE_LACKS_IDN;
#else
          CURLcode result = Curl_idn_decode(u->host, &allochost);
          if(result)
            return (result == CURLE_OUT_OF_MEMORY) ?
              CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
#endif
        }
      }
      else if(depunyfy) {
        if(Curl_is_ASCII_name(u->host) && !strncmp("xn--", u->host, 4)) {
#ifndef USE_IDN
          return CURLUE_LACKS_IDN;
#else
          CURLcode result = Curl_idn_encode(u->host, &allochost);
          if(result)
            /* this is the most likely error */
            return (result == CURLE_OUT_OF_MEMORY) ?
              CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
#endif
        }
      }

      if(!(flags & CURLU_NO_GUESS_SCHEME) || !u->guessed_scheme)
        msnprintf(schemebuf, sizeof(schemebuf), "%s://", scheme);
      else
        schemebuf[0] = 0;

      url = aprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                    schemebuf,
                    u->user ? u->user : "",
                    u->password ? ":": "",
                    u->password ? u->password : "",
                    options ? ";" : "",
                    options ? options : "",
                    (u->user || u->password || options) ? "@": "",
                    allochost ? allochost : u->host,
                    port ? ":": "",
                    port ? port : "",
                    u->path ? u->path : "/",
                    show_query ? "?": "",
                    u->query ? u->query : "",
                    show_fragment ? "#": "",
                    u->fragment ? u->fragment : "");
      free(allochost);
    }
    if(!url)
      return CURLUE_OUT_OF_MEMORY;
    *part = url;
    return CURLUE_OK;
  }
  default:
    ptr = NULL;
    break;
  }
  if(ptr) {
    size_t partlen = strlen(ptr);
    size_t i = 0;
    *part = Curl_memdup0(ptr, partlen);
    if(!*part)
      return CURLUE_OUT_OF_MEMORY;
    if(plusdecode) {
      /* convert + to space */
      char *plus = *part;
      for(i = 0; i < partlen; ++plus, i++) {
        if(*plus == '+')
          *plus = ' ';
      }
    }
    if(urldecode) {
      char *decoded;
      size_t dlen;
      /* this unconditional rejection of control bytes is documented
         API behavior */
      CURLcode res = Curl_urldecode(*part, 0, &decoded, &dlen, REJECT_CTRL);
      free(*part);
      if(res) {
        *part = NULL;
        return CURLUE_URLDECODE;
      }
      *part = decoded;
      partlen = dlen;
    }
    if(urlencode) {
      struct dynbuf enc;
      CURLUcode uc;
      Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
      uc = urlencode_str(&enc, *part, partlen, TRUE, what == CURLUPART_QUERY);
      if(uc)
        return uc;
      free(*part);
      *part = Curl_dyn_ptr(&enc);
    }
    else if(punycode) {
      if(!Curl_is_ASCII_name(u->host)) {
#ifndef USE_IDN
        return CURLUE_LACKS_IDN;
#else
        char *allochost;
        CURLcode result = Curl_idn_decode(*part, &allochost);
        if(result)
          return (result == CURLE_OUT_OF_MEMORY) ?
            CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
        free(*part);
        *part = allochost;
#endif
      }
    }
    else if(depunyfy) {
      if(Curl_is_ASCII_name(u->host)  && !strncmp("xn--", u->host, 4)) {
#ifndef USE_IDN
        return CURLUE_LACKS_IDN;
#else
        char *allochost;
        CURLcode result = Curl_idn_encode(*part, &allochost);
        if(result)
          return (result == CURLE_OUT_OF_MEMORY) ?
            CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
        free(*part);
        *part = allochost;
#endif
      }
    }

    return CURLUE_OK;
  }
  else
    return ifmissing;
}

static void free_urlhandle(struct Curl_URL *u)
{
  free(u->scheme);
  free(u->user);
  free(u->password);
  free(u->options);
  free(u->host);
  free(u->zoneid);
  free(u->port);
  free(u->path);
  free(u->query);
  free(u->fragment);
}

void curl_url_cleanup(CURLU *u)
{
  if(u) {
    free_urlhandle(u);
    free(u);
  }
}

/* Portable, consistent toupper. Do not use toupper() because its behavior is
   altered by the current locale. */
char Curl_raw_toupper(char in)
{
  return (char)touppermap[(unsigned char) in];
}

static int ncasecompare(const char *first, const char *second, size_t max)
{
  while(*first && *second && max) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second))
      return 0;
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return Curl_raw_toupper(*first) == Curl_raw_toupper(*second);
}

int curl_strnequal(const char *first, const char *second, size_t max)
{
  if(first && second)
    /* both pointers point to something then compare them */
    return ncasecompare(first, second, max);

  /* if both pointers are NULL then treat them as equal if max is non-zero */
  return (NULL == first && NULL == second && max);
}

/* int
 * inet_pton4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it is returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton4(const char *src, unsigned char *dst)
{
  static const char digits[] = "0123456789";
  int saw_digit, octets, ch;
  unsigned char tmp[INADDRSZ], *tp;

  saw_digit = 0;
  octets = 0;
  tp = tmp;
  *tp = 0;
  while((ch = *src++) != '\0') {
    const char *pch;

    pch = strchr(digits, ch);
    if(pch) {
      unsigned int val = (unsigned int)(*tp * 10) +
                         (unsigned int)(pch - digits);

      if(saw_digit && *tp == 0)
        return (0);
      if(val > 255)
        return (0);
      *tp = (unsigned char)val;
      if(!saw_digit) {
        if(++octets > 4)
          return (0);
        saw_digit = 1;
      }
    }
    else if(ch == '.' && saw_digit) {
      if(octets == 4)
        return (0);
      *++tp = 0;
      saw_digit = 0;
    }
    else
      return (0);
  }
  if(octets < 4)
    return (0);
  memcpy(dst, tmp, INADDRSZ);
  return (1);
}

/* int
 * inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it is returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton6(const char *src, unsigned char *dst)
{
  static const char xdigits_l[] = "0123456789abcdef",
    xdigits_u[] = "0123456789ABCDEF";
  unsigned char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
  const char *curtok;
  int ch, saw_xdigit;
  size_t val;

  memset((tp = tmp), 0, IN6ADDRSZ);
  endp = tp + IN6ADDRSZ;
  colonp = NULL;
  /* Leading :: requires some special handling. */
  if(*src == ':')
    if(*++src != ':')
      return (0);
  curtok = src;
  saw_xdigit = 0;
  val = 0;
  while((ch = *src++) != '\0') {
    const char *xdigits;
    const char *pch;

    pch = strchr((xdigits = xdigits_l), ch);
    if(!pch)
      pch = strchr((xdigits = xdigits_u), ch);
    if(pch) {
      val <<= 4;
      val |= (pch - xdigits);
      if(++saw_xdigit > 4)
        return (0);
      continue;
    }
    if(ch == ':') {
      curtok = src;
      if(!saw_xdigit) {
        if(colonp)
          return (0);
        colonp = tp;
        continue;
      }
      if(tp + INT16SZ > endp)
        return (0);
      *tp++ = (unsigned char) ((val >> 8) & 0xff);
      *tp++ = (unsigned char) (val & 0xff);
      saw_xdigit = 0;
      val = 0;
      continue;
    }
    if(ch == '.' && ((tp + INADDRSZ) <= endp) &&
        inet_pton4(curtok, tp) > 0) {
      tp += INADDRSZ;
      saw_xdigit = 0;
      break;    /* '\0' was seen by inet_pton4(). */
    }
    return (0);
  }
  if(saw_xdigit) {
    if(tp + INT16SZ > endp)
      return (0);
    *tp++ = (unsigned char) ((val >> 8) & 0xff);
    *tp++ = (unsigned char) (val & 0xff);
  }
  if(colonp) {
    /*
     * Since some memmove()'s erroneously fail to handle
     * overlapping regions, we will do the shift by hand.
     */
    const ssize_t n = tp - colonp;
    ssize_t i;

    if(tp == endp)
      return (0);
    for(i = 1; i <= n; i++) {
      *(endp - i) = *(colonp + n - i);
      *(colonp + n - i) = 0;
    }
    tp = endp;
  }
  if(tp != endp)
    return (0);
  memcpy(dst, tmp, IN6ADDRSZ);
  return (1);
}

/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address was not valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * notice:
 *      On Windows we store the error in the thread errno, not
 *      in the Winsock error code. This is to avoid losing the
 *      actual last Winsock error. When this function returns
 *      -1, check errno not SOCKERRNO.
 * author:
 *      Paul Vixie, 1996.
 */
extern int errno;
int
Curl_inet_pton(int af, const char *src, void *dst)
{
  switch(af) {
  case AF_INET:
    return (inet_pton4(src, (unsigned char *)dst));
  case AF_INET6:
    return (inet_pton6(src, (unsigned char *)dst));
  default:
    errno = EAFNOSUPPORT;
    return (-1);
  }
  /* NOTREACHED */
}

/*
 * Format an IPv4 address, more or less like inet_ntop().
 *
 * Returns `dst' (as a const)
 * Note:
 *  - uses no statics
 *  - takes a unsigned char* not an in_addr as input
 */
static char *inet_ntop4(const unsigned char *src, char *dst, size_t size)
{
  char tmp[sizeof("255.255.255.255")];
  size_t len;

  DEBUGASSERT(size >= 16);

  tmp[0] = '\0';
  (void)msnprintf(tmp, sizeof(tmp), "%d.%d.%d.%d",
                  ((int)((unsigned char)src[0])) & 0xff,
                  ((int)((unsigned char)src[1])) & 0xff,
                  ((int)((unsigned char)src[2])) & 0xff,
                  ((int)((unsigned char)src[3])) & 0xff);

  len = strlen(tmp);
  if(len == 0 || len >= size) {
    errno = ENOSPC;
    return (NULL);
  }
  strcpy(dst, tmp);
  return dst;
}

/*
 * Convert IPv6 binary address into presentation (printable) format.
 */
static char *inet_ntop6(const unsigned char *src, char *dst, size_t size)
{
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size. On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays. All the world's not a VAX.
   */
  char tmp[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
  char *tp;
  struct {
    int base;
    int len;
  } best, cur;
  unsigned int words[IN6ADDRSZ / INT16SZ];
  int i;

  /* Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, '\0', sizeof(words));
  for(i = 0; i < IN6ADDRSZ; i++)
    words[i/2] |= ((unsigned int)src[i] << ((1 - (i % 2)) << 3));

  best.base = -1;
  cur.base  = -1;
  best.len = 0;
  cur.len = 0;

  for(i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
    if(words[i] == 0) {
      if(cur.base == -1) {
        cur.base = i; cur.len = 1;
      }
      else
        cur.len++;
    }
    else if(cur.base != -1) {
      if(best.base == -1 || cur.len > best.len)
        best = cur;
      cur.base = -1;
    }
  }
  if((cur.base != -1) && (best.base == -1 || cur.len > best.len))
    best = cur;
  if(best.base != -1 && best.len < 2)
    best.base = -1;
  /* Format the result. */
  tp = tmp;
  for(i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
    /* Are we inside the best run of 0x00's? */
    if(best.base != -1 && i >= best.base && i < (best.base + best.len)) {
      if(i == best.base)
        *tp++ = ':';
      continue;
    }

    /* Are we following an initial run of 0x00s or any real hex?
     */
    if(i)
      *tp++ = ':';

    /* Is this address an encapsulated IPv4?
     */
    if(i == 6 && best.base == 0 &&
        (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
      if(!inet_ntop4(src + 12, tp, sizeof(tmp) - (tp - tmp))) {
        errno = ENOSPC;
        return (NULL);
      }
      tp += strlen(tp);
      break;
    }
    tp += msnprintf(tp, 5, "%x", words[i]);
  }

  /* Was it a trailing run of 0x00's?
   */
  if(best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
    *tp++ = ':';
  *tp++ = '\0';

  /* Check for overflow, copy, and we are done.
   */
  if((size_t)(tp - tmp) > size) {
    errno = ENOSPC;
    return (NULL);
  }
  strcpy(dst, tmp);
  return dst;
}

/*
 * Convert a network format address to presentation format.
 *
 * Returns pointer to presentation format address (`buf').
 * Returns NULL on error and errno set with the specific
 * error, EAFNOSUPPORT or ENOSPC.
 *
 * On Windows we store the error in the thread errno, not in the Winsock error
 * code. This is to avoid losing the actual last Winsock error. When this
 * function returns NULL, check errno not SOCKERRNO.
 */
char *Curl_inet_ntop(int af, const void *src, char *buf, size_t size)
{
  switch(af) {
  case AF_INET:
    return inet_ntop4((const unsigned char *)src, buf, size);
  case AF_INET6:
    return inet_ntop6((const unsigned char *)src, buf, size);
  default:
    errno = EAFNOSUPPORT;
    return NULL;
  }
}

/* this assumes 'hostname' now starts with [ */
static CURLUcode ipv6_parse(struct Curl_URL *u, char *hostname,
                            size_t hlen) /* length of hostname */
{
  size_t len;
  DEBUGASSERT(*hostname == '[');
  if(hlen < 4) /* '[::]' is the shortest possible valid string */
    return CURLUE_BAD_IPV6;
  hostname++;
  hlen -= 2;

  /* only valid IPv6 letters are ok */
  len = strspn(hostname, "0123456789abcdefABCDEF:.");

  if(hlen != len) {
    hlen = len;
    if(hostname[len] == '%') {
      /* this could now be '%[zone id]' */
      char zoneid[16];
      int i = 0;
      char *h = &hostname[len + 1];
      /* pass '25' if present and is a URL encoded percent sign */
      if(!strncmp(h, "25", 2) && h[2] && (h[2] != ']'))
        h += 2;
      while(*h && (*h != ']') && (i < 15))
        zoneid[i++] = *h++;
      if(!i || (']' != *h))
        return CURLUE_BAD_IPV6;
      zoneid[i] = 0;
      u->zoneid = strdup(zoneid);
      if(!u->zoneid)
        return CURLUE_OUT_OF_MEMORY;
      hostname[len] = ']'; /* insert end bracket */
      hostname[len + 1] = 0; /* terminate the hostname */
    }
    else
      return CURLUE_BAD_IPV6;
    /* hostname is fine */
  }

  /* Normalize the IPv6 address */
  {
    char dest[16]; /* fits a binary IPv6 address */
    hostname[hlen] = 0; /* end the address there */
    if(1 != Curl_inet_pton(AF_INET6, hostname, dest))
      return CURLUE_BAD_IPV6;
    if(Curl_inet_ntop(AF_INET6, dest, hostname, hlen)) {
      hlen = strlen(hostname); /* might be shorter now */
      hostname[hlen + 1] = 0;
    }
    hostname[hlen] = ']'; /* restore ending bracket */
  }
  return CURLUE_OK;
}

static CURLUcode hostname_check(struct Curl_URL *u, char *hostname,
                                size_t hlen) /* length of hostname */
{
  size_t len;
  DEBUGASSERT(hostname);

  if(!hlen)
    return CURLUE_NO_HOST;
  else if(hostname[0] == '[')
    return ipv6_parse(u, hostname, hlen);
  else {
    /* letters from the second string are not ok */
    len = strcspn(hostname, " \r\n\t/:#?!@{}[]\\$\'\"^`*<>=;,+&()%");
    if(hlen != len)
      /* hostname with bad content */
      return CURLUE_BAD_HOSTNAME;
  }
  return CURLUE_OK;
}

static int ipv4_normalize(struct dynbuf *host)
{
  bool done = FALSE;
  int n = 0;
  const char *c = Curl_dyn_ptr(host);
  unsigned long parts[4] = {0, 0, 0, 0};
  CURLcode result = CURLE_OK;

  if(*c == '[')
    return HOST_IPV6;

  errno = 0; /* for strtoul */
  while(!done) {
    char *endp = NULL;
    unsigned long l;
    if(!ISDIGIT(*c))
      /* most importantly this does not allow a leading plus or minus */
      return HOST_NAME;
    l = strtoul(c, &endp, 0);
    if(errno)
      return HOST_NAME;
#if SIZEOF_LONG > 4
    /* a value larger than 32 bits */
    if(l > UINT_MAX)
      return HOST_NAME;
#endif

    parts[n] = l;
    c = endp;

    switch(*c) {
    case '.':
      if(n == 3)
        return HOST_NAME;
      n++;
      c++;
      break;

    case '\0':
      done = TRUE;
      break;

    default:
      return HOST_NAME;
    }
  }

  switch(n) {
  case 0: /* a -- 32 bits */
    Curl_dyn_reset(host);

    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0] >> 24),
                           (unsigned int)((parts[0] >> 16) & 0xff),
                           (unsigned int)((parts[0] >> 8) & 0xff),
                           (unsigned int)(parts[0] & 0xff));
    break;
  case 1: /* a.b -- 8.24 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xffffff))
      return HOST_NAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0]),
                           (unsigned int)((parts[1] >> 16) & 0xff),
                           (unsigned int)((parts[1] >> 8) & 0xff),
                           (unsigned int)(parts[1] & 0xff));
    break;
  case 2: /* a.b.c -- 8.8.16 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xffff))
      return HOST_NAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0]),
                           (unsigned int)(parts[1]),
                           (unsigned int)((parts[2] >> 8) & 0xff),
                           (unsigned int)(parts[2] & 0xff));
    break;
  case 3: /* a.b.c.d -- 8.8.8.8 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff) ||
       (parts[3] > 0xff))
      return HOST_NAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0]),
                           (unsigned int)(parts[1]),
                           (unsigned int)(parts[2]),
                           (unsigned int)(parts[3]));
    break;
  }
  if(result)
    return HOST_ERROR;
  return HOST_IPV4;
}

/*
 * Curl_parse_login_details()
 *
 * This is used to parse a login string for username, password and options in
 * the following formats:
 *
 *   user
 *   user:password
 *   user:password;options
 *   user;options
 *   user;options:password
 *   :password
 *   :password;options
 *   ;options
 *   ;options:password
 *
 * Parameters:
 *
 * login    [in]     - login string.
 * len      [in]     - length of the login string.
 * userp    [in/out] - address where a pointer to newly allocated memory
 *                     holding the user will be stored upon completion.
 * passwdp  [in/out] - address where a pointer to newly allocated memory
 *                     holding the password will be stored upon completion.
 * optionsp [in/out] - OPTIONAL address where a pointer to newly allocated
 *                     memory holding the options will be stored upon
 *                     completion.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_parse_login_details(const char *login, const size_t len,
                                  char **userp, char **passwdp,
                                  char **optionsp)
{
  char *ubuf = NULL;
  char *pbuf = NULL;
  const char *psep = NULL;
  const char *osep = NULL;
  size_t ulen;
  size_t plen;
  size_t olen;

  DEBUGASSERT(userp);
  DEBUGASSERT(passwdp);

  /* Attempt to find the password separator */
  psep = memchr(login, ':', len);

  /* Attempt to find the options separator */
  if(optionsp)
    osep = memchr(login, ';', len);

  /* Calculate the portion lengths */
  ulen = (psep ?
          (size_t)(osep && psep > osep ? osep - login : psep - login) :
          (osep ? (size_t)(osep - login) : len));
  plen = (psep ?
          (osep && osep > psep ? (size_t)(osep - psep) :
           (size_t)(login + len - psep)) - 1 : 0);
  olen = (osep ?
          (psep && psep > osep ? (size_t)(psep - osep) :
           (size_t)(login + len - osep)) - 1 : 0);

  /* Clone the user portion buffer, which can be zero length */
  ubuf = Curl_memdup0(login, ulen);
  if(!ubuf)
    goto error;

  /* Clone the password portion buffer */
  if(psep) {
    pbuf = Curl_memdup0(&psep[1], plen);
    if(!pbuf)
      goto error;
  }

  /* Allocate the options portion buffer */
  if(optionsp) {
    char *obuf = NULL;
    if(olen) {
      obuf = Curl_memdup0(&osep[1], olen);
      if(!obuf)
        goto error;
    }
    *optionsp = obuf;
  }
  *userp = ubuf;
  *passwdp = pbuf;
  return CURLE_OK;
error:
  free(ubuf);
  free(pbuf);
  return CURLE_OUT_OF_MEMORY;
}

/*
 * parse_hostname_login()
 *
 * Parse the login details (username, password and options) from the URL and
 * strip them out of the hostname
 *
 */
static CURLUcode parse_hostname_login(struct Curl_URL *u,
                                      const char *login,
                                      size_t len,
                                      unsigned int flags,
                                      size_t *offset) /* to the hostname */
{
  CURLUcode result = CURLUE_OK;
  CURLcode ccode;
  char *userp = NULL;
  char *passwdp = NULL;
  char *optionsp = NULL;
  const struct Curl_handler *h = NULL;

  /* At this point, we assume all the other special cases have been taken
   * care of, so the host is at most
   *
   *   [user[:password][;options]]@]hostname
   *
   * We need somewhere to put the embedded details, so do that first.
   */
  char *ptr;

  DEBUGASSERT(login);

  *offset = 0;
  ptr = memchr(login, '@', len);
  if(!ptr)
    goto out;

  /* We will now try to extract the
   * possible login information in a string like:
   * ftp://user:password@ftp.my.site:8021/README */
  ptr++;

  /* if this is a known scheme, get some details */
  if(u->scheme)
    h = Curl_get_scheme_handler(u->scheme);

  /* We could use the login information in the URL so extract it. Only parse
     options if the handler says we should. Note that 'h' might be NULL! */
  ccode = Curl_parse_login_details(login, ptr - login - 1,
                                   &userp, &passwdp,
                                   (h && (h->flags & PROTOPT_URLOPTIONS)) ?
                                   &optionsp : NULL);
  if(ccode) {
    result = CURLUE_BAD_LOGIN;
    goto out;
  }

  if(userp) {
    if(flags & CURLU_DISALLOW_USER) {
      /* Option DISALLOW_USER is set and URL contains username. */
      result = CURLUE_USER_NOT_ALLOWED;
      goto out;
    }
    free(u->user);
    u->user = userp;
  }

  if(passwdp) {
    free(u->password);
    u->password = passwdp;
  }

  if(optionsp) {
    free(u->options);
    u->options = optionsp;
  }

  /* the hostname starts at this offset */
  *offset = ptr - login;
  return CURLUE_OK;

out:

  free(userp);
  free(passwdp);
  free(optionsp);
  u->user = NULL;
  u->password = NULL;
  u->options = NULL;

  return result;
}

/*
 * Set a new (smaller) length.
 */
CURLcode Curl_dyn_setlen(struct dynbuf *s, size_t set)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  if(set > s->leng)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  s->leng = set;
  s->bufr[s->leng] = 0;
  return CURLE_OK;
}


UNITTEST CURLUcode Curl_parse_port(struct Curl_URL *u, struct dynbuf *host,
                                   bool has_scheme)
{
  char *portptr;
  char *hostname = Curl_dyn_ptr(host);
  /*
   * Find the end of an IPv6 address on the ']' ending bracket.
   */
  if(hostname[0] == '[') {
    portptr = strchr(hostname, ']');
    if(!portptr)
      return CURLUE_BAD_IPV6;
    portptr++;
    /* this is a RFC2732-style specified IP-address */
    if(*portptr) {
      if(*portptr != ':')
        return CURLUE_BAD_PORT_NUMBER;
    }
    else
      portptr = NULL;
  }
  else
    portptr = strchr(hostname, ':');

  if(portptr) {
    char *rest = NULL;
    unsigned long port;
    size_t keep = portptr - hostname;

    /* Browser behavior adaptation. If there is a colon with no digits after,
       just cut off the name there which makes us ignore the colon and just
       use the default port. Firefox, Chrome and Safari all do that.

       Do not do it if the URL has no scheme, to make something that looks like
       a scheme not work!
    */
    Curl_dyn_setlen(host, keep);
    portptr++;
    if(!*portptr)
      return has_scheme ? CURLUE_OK : CURLUE_BAD_PORT_NUMBER;

    if(!ISDIGIT(*portptr))
      return CURLUE_BAD_PORT_NUMBER;

    errno = 0;
    port = strtoul(portptr, &rest, 10);  /* Port number must be decimal */

    if(errno || (port > 0xffff) || *rest)
      return CURLUE_BAD_PORT_NUMBER;

    u->portnum = (unsigned short) port;
    /* generate a new port number string to get rid of leading zeroes etc */
    free(u->port);
    u->port = aprintf("%ld", port);
    if(!u->port)
      return CURLUE_OUT_OF_MEMORY;
  }

  return CURLUE_OK;
}

/*
 * Concatenate a relative URL to a base URL making it absolute.
 * URL-encodes any spaces.
 * The returned pointer must be freed by the caller unless NULL
 * (returns NULL on out of memory).
 *
 * Note that this function destroys the 'base' string.
 */
static CURLcode concat_url(char *base, const char *relurl, char **newurl)
{
  /***
   TRY to append this new path to the old URL
   to the right of the host part. Oh crap, this is doomed to cause
   problems in the future...
  */
  struct dynbuf newest;
  char *protsep;
  char *pathsep;
  bool host_changed = FALSE;
  const char *useurl = relurl;
  CURLcode result = CURLE_OK;
  CURLUcode uc;
  bool skip_slash = FALSE;
  *newurl = NULL;

  /* protsep points to the start of the hostname */
  protsep = strstr(base, "//");
  if(!protsep)
    protsep = base;
  else
    protsep += 2; /* pass the slashes */

  if('/' != relurl[0]) {
    int level = 0;

    /* First we need to find out if there is a ?-letter in the URL,
       and cut it and the right-side of that off */
    pathsep = strchr(protsep, '?');
    if(pathsep)
      *pathsep = 0;

    /* we have a relative path to append to the last slash if there is one
       available, or the new URL is just a query string (starts with a '?') or
       a fragment (starts with '#') we append the new one at the end of the
       current URL */
    if((useurl[0] != '?') && (useurl[0] != '#')) {
      pathsep = strrchr(protsep, '/');
      if(pathsep)
        *pathsep = 0;

      /* Check if there is any slash after the hostname, and if so, remember
         that position instead */
      pathsep = strchr(protsep, '/');
      if(pathsep)
        protsep = pathsep + 1;
      else
        protsep = NULL;

      /* now deal with one "./" or any amount of "../" in the newurl
         and act accordingly */

      if((useurl[0] == '.') && (useurl[1] == '/'))
        useurl += 2; /* just skip the "./" */

      while((useurl[0] == '.') &&
            (useurl[1] == '.') &&
            (useurl[2] == '/')) {
        level++;
        useurl += 3; /* pass the "../" */
      }

      if(protsep) {
        while(level--) {
          /* cut off one more level from the right of the original URL */
          pathsep = strrchr(protsep, '/');
          if(pathsep)
            *pathsep = 0;
          else {
            *protsep = 0;
            break;
          }
        }
      }
    }
    else
      skip_slash = TRUE;
  }
  else {
    /* We got a new absolute path for this server */

    if(relurl[1] == '/') {
      /* the new URL starts with //, just keep the protocol part from the
         original one */
      *protsep = 0;
      useurl = &relurl[2]; /* we keep the slashes from the original, so we
                              skip the new ones */
      host_changed = TRUE;
    }
    else {
      /* cut off the original URL from the first slash, or deal with URLs
         without slash */
      pathsep = strchr(protsep, '/');
      if(pathsep) {
        /* When people use badly formatted URLs, such as
           "http://www.example.com?dir=/home/daniel" we must not use the first
           slash, if there is a ?-letter before it! */
        char *sep = strchr(protsep, '?');
        if(sep && (sep < pathsep))
          pathsep = sep;
        *pathsep = 0;
      }
      else {
        /* There was no slash. Now, since we might be operating on a badly
           formatted URL, such as "http://www.example.com?id=2380" which does
           not use a slash separator as it is supposed to, we need to check
           for a ?-letter as well! */
        pathsep = strchr(protsep, '?');
        if(pathsep)
          *pathsep = 0;
      }
    }
  }

  Curl_dyn_init(&newest, CURL_MAX_INPUT_LENGTH);

  /* copy over the root URL part */
  result = Curl_dyn_add(&newest, base);
  if(result)
    return result;

  /* check if we need to append a slash */
  if(('/' == useurl[0]) || (protsep && !*protsep) || skip_slash)
    ;
  else {
    result = Curl_dyn_addn(&newest, "/", 1);
    if(result)
      return result;
  }

  /* then append the new piece on the right side */
  uc = urlencode_str(&newest, useurl, strlen(useurl), !host_changed,
                     FALSE);
  if(uc)
    return (uc == CURLUE_TOO_LARGE) ? CURLE_TOO_LARGE : CURLE_OUT_OF_MEMORY;

  *newurl = Curl_dyn_ptr(&newest);
  return CURLE_OK;
}

/* scan for byte values <= 31, 127 and sometimes space */
static CURLUcode junkscan(const char *url, size_t *urllen, unsigned int flags)
{
  static const char badbytes[]={
    /* */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x7f, 0x00 /* null-terminate */
  };
  size_t n = strlen(url);
  size_t nfine;

  if(n > CURL_MAX_INPUT_LENGTH)
    /* excessive input length */
    return CURLUE_MALFORMED_INPUT;

  nfine = strcspn(url, badbytes);
  if((nfine != n) ||
     (!(flags & CURLU_ALLOW_SPACE) && strchr(url, ' ')))
    return CURLUE_MALFORMED_INPUT;

  *urllen = n;
  return CURLUE_OK;
}

/* Copy a lower case version of the string from src to dest. The
 * strings may overlap. No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void Curl_strntolower(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = Curl_raw_tolower(*src);
  } while(*src++ && --n);
}

UNITTEST int dedotdotify(const char *input, size_t clen, char **outp)
{
  char *outptr;
  const char *endp = &input[clen];
  char *out;

  *outp = NULL;
  /* the path always starts with a slash, and a slash has not dot */
  if((clen < 2) || !memchr(input, '.', clen))
    return 0;

  out = malloc(clen + 1);
  if(!out)
    return 1; /* out of memory */

  *out = 0; /* null-terminates, for inputs like "./" */
  outptr = out;

  do {
    bool dotdot = TRUE;
    if(*input == '.') {
      /*  A. If the input buffer begins with a prefix of "../" or "./", then
          remove that prefix from the input buffer; otherwise, */

      if(!strncmp("./", input, 2)) {
        input += 2;
        clen -= 2;
      }
      else if(!strncmp("../", input, 3)) {
        input += 3;
        clen -= 3;
      }
      /*  D. if the input buffer consists only of "." or "..", then remove
          that from the input buffer; otherwise, */

      else if(!strcmp(".", input) || !strcmp("..", input) ||
              !strncmp(".?", input, 2) || !strncmp("..?", input, 3)) {
        *out = 0;
        break;
      }
      else
        dotdot = FALSE;
    }
    else if(*input == '/') {
      /*  B. if the input buffer begins with a prefix of "/./" or "/.", where
          "."  is a complete path segment, then replace that prefix with "/" in
          the input buffer; otherwise, */
      if(!strncmp("/./", input, 3)) {
        input += 2;
        clen -= 2;
      }
      else if(!strcmp("/.", input) || !strncmp("/.?", input, 3)) {
        *outptr++ = '/';
        *outptr = 0;
        break;
      }

      /*  C. if the input buffer begins with a prefix of "/../" or "/..",
          where ".." is a complete path segment, then replace that prefix with
          "/" in the input buffer and remove the last segment and its
          preceding "/" (if any) from the output buffer; otherwise, */

      else if(!strncmp("/../", input, 4)) {
        input += 3;
        clen -= 3;
        /* remove the last segment from the output buffer */
        while(outptr > out) {
          outptr--;
          if(*outptr == '/')
            break;
        }
        *outptr = 0; /* null-terminate where it stops */
      }
      else if(!strcmp("/..", input) || !strncmp("/..?", input, 4)) {
        /* remove the last segment from the output buffer */
        while(outptr > out) {
          outptr--;
          if(*outptr == '/')
            break;
        }
        *outptr++ = '/';
        *outptr = 0; /* null-terminate where it stops */
        break;
      }
      else
        dotdot = FALSE;
    }
    else
      dotdot = FALSE;

    if(!dotdot) {
      /*  E. move the first path segment in the input buffer to the end of
          the output buffer, including the initial "/" character (if any) and
          any subsequent characters up to, but not including, the next "/"
          character or the end of the input buffer. */

      do {
        *outptr++ = *input++;
        clen--;
      } while(*input && (*input != '/') && (*input != '?'));
      *outptr = 0;
    }

    /* continue until end of path */
  } while(input < endp);

  *outp = out;
  return 0; /* success */
}

/* if necessary, replace the host content with a URL decoded version */
static CURLUcode urldecode_host(struct dynbuf *host)
{
  char *per = NULL;
  const char *hostname = Curl_dyn_ptr(host);
  per = strchr(hostname, '%');
  if(!per)
    /* nothing to decode */
    return CURLUE_OK;
  else {
    /* encoded */
    size_t dlen;
    char *decoded;
    CURLcode result = Curl_urldecode(hostname, 0, &decoded, &dlen,
                                     REJECT_CTRL);
    if(result)
      return CURLUE_BAD_HOSTNAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addn(host, decoded, dlen);
    free(decoded);
    if(result)
      return cc2cu(result);
  }

  return CURLUE_OK;
}

static CURLUcode parse_authority(struct Curl_URL *u,
                                 const char *auth, size_t authlen,
                                 unsigned int flags,
                                 struct dynbuf *host,
                                 bool has_scheme)
{
  size_t offset;
  CURLUcode uc;
  CURLcode result;

  /*
   * Parse the login details and strip them out of the hostname.
   */
  uc = parse_hostname_login(u, auth, authlen, flags, &offset);
  if(uc)
    goto out;

  result = Curl_dyn_addn(host, auth + offset, authlen - offset);
  if(result) {
    uc = cc2cu(result);
    goto out;
  }

  uc = Curl_parse_port(u, host, has_scheme);
  if(uc)
    goto out;

  if(!Curl_dyn_len(host))
    return CURLUE_NO_HOST;

  switch(ipv4_normalize(host)) {
  case HOST_IPV4:
    break;
  case HOST_IPV6:
    uc = ipv6_parse(u, Curl_dyn_ptr(host), Curl_dyn_len(host));
    break;
  case HOST_NAME:
    uc = urldecode_host(host);
    if(!uc)
      uc = hostname_check(u, Curl_dyn_ptr(host), Curl_dyn_len(host));
    break;
  case HOST_ERROR:
    uc = CURLUE_OUT_OF_MEMORY;
    break;
  default:
    uc = CURLUE_BAD_HOSTNAME; /* Bad IPv4 address even */
    break;
  }

out:
  return uc;
}

/*
 * Returns the length of the scheme if the given URL is absolute (as opposed
 * to relative). Stores the scheme in the buffer if TRUE and 'buf' is
 * non-NULL. The buflen must be larger than MAX_SCHEME_LEN if buf is set.
 *
 * If 'guess_scheme' is TRUE, it means the URL might be provided without
 * scheme.
 */
size_t Curl_is_absolute_url(const char *url, char *buf, size_t buflen,
                            bool guess_scheme)
{
  size_t i = 0;
  DEBUGASSERT(!buf || (buflen > MAX_SCHEME_LEN));
  (void)buflen; /* only used in debug-builds */
  if(buf)
    buf[0] = 0; /* always leave a defined value in buf */
#ifdef _WIN32
  if(guess_scheme && STARTS_WITH_DRIVE_PREFIX(url))
    return 0;
#endif
  if(ISALPHA(url[0]))
    for(i = 1; i < MAX_SCHEME_LEN; ++i) {
      char s = url[i];
      if(s && (ISALNUM(s) || (s == '+') || (s == '-') || (s == '.') )) {
        /* RFC 3986 3.1 explains:
           scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        */
      }
      else {
        break;
      }
    }
  if(i && (url[i] == ':') && ((url[i + 1] == '/') || !guess_scheme)) {
    /* If this does not guess scheme, the scheme always ends with the colon so
       that this also detects data: URLs etc. In guessing mode, data: could
       be the hostname "data" with a specified port number. */

    /* the length of the scheme is the name part only */
    size_t len = i;
    if(buf) {
      Curl_strntolower(buf, url, i);
      buf[i] = 0;
    }
    return len;
  }
  return 0;
}

static CURLUcode parseurl(const char *url, CURLU *u, unsigned int flags)
{
  const char *path;
  size_t pathlen;
  char *query = NULL;
  char *fragment = NULL;
  char schemebuf[MAX_SCHEME_LEN + 1];
  size_t schemelen = 0;
  size_t urllen;
  CURLUcode result = CURLUE_OK;
  size_t fraglen = 0;
  struct dynbuf host;

  DEBUGASSERT(url);

  Curl_dyn_init(&host, CURL_MAX_INPUT_LENGTH);

  result = junkscan(url, &urllen, flags);
  if(result)
    goto fail;

  schemelen = Curl_is_absolute_url(url, schemebuf, sizeof(schemebuf),
                                   flags & (CURLU_GUESS_SCHEME|
                                            CURLU_DEFAULT_SCHEME));

  /* handle the file: scheme */
  if(schemelen && !strcmp(schemebuf, "file")) {
    bool uncpath = FALSE;
    if(urllen <= 6) {
      /* file:/ is not enough to actually be a complete file: URL */
      result = CURLUE_BAD_FILE_URL;
      goto fail;
    }

    /* path has been allocated large enough to hold this */
    path = (char *)&url[5];
    pathlen = urllen - 5;

    u->scheme = strdup("file");
    if(!u->scheme) {
      result = CURLUE_OUT_OF_MEMORY;
      goto fail;
    }

    /* Extra handling URLs with an authority component (i.e. that start with
     * "file://")
     *
     * We allow omitted hostname (e.g. file:/<path>) -- valid according to
     * RFC 8089, but not the (current) WHAT-WG URL spec.
     */
    if(path[0] == '/' && path[1] == '/') {
      /* swallow the two slashes */
      const char *ptr = &path[2];

      /*
       * According to RFC 8089, a file: URL can be reliably dereferenced if:
       *
       *  o it has no/blank hostname, or
       *
       *  o the hostname matches "localhost" (case-insensitively), or
       *
       *  o the hostname is a FQDN that resolves to this machine, or
       *
       *  o it is an UNC String transformed to an URI (Windows only, RFC 8089
       *    Appendix E.3).
       *
       * For brevity, we only consider URLs with empty, "localhost", or
       * "127.0.0.1" hostnames as local, otherwise as an UNC String.
       *
       * Additionally, there is an exception for URLs with a Windows drive
       * letter in the authority (which was accidentally omitted from RFC 8089
       * Appendix E, but believe me, it was meant to be there. --MK)
       */
      if(ptr[0] != '/' && !STARTS_WITH_URL_DRIVE_PREFIX(ptr)) {
        /* the URL includes a hostname, it must match "localhost" or
           "127.0.0.1" to be valid */
        if(checkprefix("localhost/", ptr) ||
           checkprefix("127.0.0.1/", ptr)) {
          ptr += 9; /* now points to the slash after the host */
        }
        else {
#if defined(_WIN32)
          size_t len;

          /* the hostname, NetBIOS computer name, can not contain disallowed
             chars, and the delimiting slash character must be appended to the
             hostname */
          path = strpbrk(ptr, "/\\:*?\"<>|");
          if(!path || *path != '/') {
            result = CURLUE_BAD_FILE_URL;
            goto fail;
          }

          len = path - ptr;
          if(len) {
            CURLcode code = Curl_dyn_addn(&host, ptr, len);
            if(code) {
              result = cc2cu(code);
              goto fail;
            }
            uncpath = TRUE;
          }

          ptr -= 2; /* now points to the // before the host in UNC */
#else
          /* Invalid file://hostname/, expected localhost or 127.0.0.1 or
             none */
          result = CURLUE_BAD_FILE_URL;
          goto fail;
#endif
        }
      }

      path = ptr;
      pathlen = urllen - (ptr - url);
    }

    if(!uncpath)
      /* no host for file: URLs by default */
      Curl_dyn_reset(&host);

#if !defined(_WIN32) && !defined(MSDOS) && !defined(__CYGWIN__)
    /* Do not allow Windows drive letters when not in Windows.
     * This catches both "file:/c:" and "file:c:" */
    if(('/' == path[0] && STARTS_WITH_URL_DRIVE_PREFIX(&path[1])) ||
       STARTS_WITH_URL_DRIVE_PREFIX(path)) {
      /* File drive letters are only accepted in MS-DOS/Windows */
      result = CURLUE_BAD_FILE_URL;
      goto fail;
    }
#else
    /* If the path starts with a slash and a drive letter, ditch the slash */
    if('/' == path[0] && STARTS_WITH_URL_DRIVE_PREFIX(&path[1])) {
      /* This cannot be done with strcpy, as the memory chunks overlap! */
      path++;
      pathlen--;
    }
#endif

  }
  else {
    /* clear path */
    const char *schemep = NULL;
    const char *hostp;
    size_t hostlen;

    if(schemelen) {
      int i = 0;
      const char *p = &url[schemelen + 1];
      while((*p == '/') && (i < 4)) {
        p++;
        i++;
      }

      schemep = schemebuf;
      if(!Curl_get_scheme_handler(schemep) &&
         !(flags & CURLU_NON_SUPPORT_SCHEME)) {
        result = CURLUE_UNSUPPORTED_SCHEME;
        goto fail;
      }

      if((i < 1) || (i > 3)) {
        /* less than one or more than three slashes */
        result = CURLUE_BAD_SLASHES;
        goto fail;
      }
      hostp = p; /* hostname starts here */
    }
    else {
      /* no scheme! */

      if(!(flags & (CURLU_DEFAULT_SCHEME|CURLU_GUESS_SCHEME))) {
        result = CURLUE_BAD_SCHEME;
        goto fail;
      }
      if(flags & CURLU_DEFAULT_SCHEME)
        schemep = DEFAULT_SCHEME;

      /*
       * The URL was badly formatted, let's try without scheme specified.
       */
      hostp = url;
    }

    if(schemep) {
      u->scheme = strdup(schemep);
      if(!u->scheme) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
    }

    /* find the end of the hostname + port number */
    hostlen = strcspn(hostp, "/?#");
    path = &hostp[hostlen];

    /* this pathlen also contains the query and the fragment */
    pathlen = urllen - (path - url);
    if(hostlen) {

      result = parse_authority(u, hostp, hostlen, flags, &host, schemelen);
      if(result)
        goto fail;

      if((flags & CURLU_GUESS_SCHEME) && !schemep) {
        const char *hostname = Curl_dyn_ptr(&host);
        /* legacy curl-style guess based on hostname */
        if(checkprefix("ftp.", hostname))
          schemep = "ftp";
        else if(checkprefix("dict.", hostname))
          schemep = "dict";
        else if(checkprefix("ldap.", hostname))
          schemep = "ldap";
        else if(checkprefix("imap.", hostname))
          schemep = "imap";
        else if(checkprefix("smtp.", hostname))
          schemep = "smtp";
        else if(checkprefix("pop3.", hostname))
          schemep = "pop3";
        else
          schemep = "http";

        u->scheme = strdup(schemep);
        if(!u->scheme) {
          result = CURLUE_OUT_OF_MEMORY;
          goto fail;
        }
        u->guessed_scheme = TRUE;
      }
    }
    else if(flags & CURLU_NO_AUTHORITY) {
      /* allowed to be empty. */
      if(Curl_dyn_add(&host, "")) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
    }
    else {
      result = CURLUE_NO_HOST;
      goto fail;
    }
  }

  fragment = strchr(path, '#');
  if(fragment) {
    fraglen = pathlen - (fragment - path);
    u->fragment_present = TRUE;
    if(fraglen > 1) {
      /* skip the leading '#' in the copy but include the terminating null */
      if(flags & CURLU_URLENCODE) {
        struct dynbuf enc;
        Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
        result = urlencode_str(&enc, fragment + 1, fraglen - 1, TRUE, FALSE);
        if(result)
          goto fail;
        u->fragment = Curl_dyn_ptr(&enc);
      }
      else {
        u->fragment = Curl_memdup0(fragment + 1, fraglen - 1);
        if(!u->fragment) {
          result = CURLUE_OUT_OF_MEMORY;
          goto fail;
        }
      }
    }
    /* after this, pathlen still contains the query */
    pathlen -= fraglen;
  }

  query = memchr(path, '?', pathlen);
  if(query) {
    size_t qlen = fragment ? (size_t)(fragment - query) :
      pathlen - (query - path);
    pathlen -= qlen;
    u->query_present = TRUE;
    if(qlen > 1) {
      if(flags & CURLU_URLENCODE) {
        struct dynbuf enc;
        Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
        /* skip the leading question mark */
        result = urlencode_str(&enc, query + 1, qlen - 1, TRUE, TRUE);
        if(result)
          goto fail;
        u->query = Curl_dyn_ptr(&enc);
      }
      else {
        u->query = Curl_memdup0(query + 1, qlen - 1);
        if(!u->query) {
          result = CURLUE_OUT_OF_MEMORY;
          goto fail;
        }
      }
    }
    else {
      /* single byte query */
      u->query = strdup("");
      if(!u->query) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
    }
  }

  if(pathlen && (flags & CURLU_URLENCODE)) {
    struct dynbuf enc;
    Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
    result = urlencode_str(&enc, path, pathlen, TRUE, FALSE);
    if(result)
      goto fail;
    pathlen = Curl_dyn_len(&enc);
    path = u->path = Curl_dyn_ptr(&enc);
  }

  if(pathlen <= 1) {
    /* there is no path left or just the slash, unset */
    path = NULL;
  }
  else {
    if(!u->path) {
      u->path = Curl_memdup0(path, pathlen);
      if(!u->path) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
      path = u->path;
    }
    else if(flags & CURLU_URLENCODE)
      /* it might have encoded more than just the path so cut it */
      u->path[pathlen] = 0;

    if(!(flags & CURLU_PATH_AS_IS)) {
      /* remove ../ and ./ sequences according to RFC3986 */
      char *dedot;
      int err = dedotdotify((char *)path, pathlen, &dedot);
      if(err) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
      if(dedot) {
        free(u->path);
        u->path = dedot;
      }
    }
  }

  u->host = Curl_dyn_ptr(&host);

  return result;
fail:
  Curl_dyn_free(&host);
  free_urlhandle(u);
  return result;
}

/*
 * Parse the URL and, if successful, replace everything in the Curl_URL struct.
 */
static CURLUcode parseurl_and_replace(const char *url, CURLU *u,
                                      unsigned int flags)
{
  CURLUcode result;
  CURLU tmpurl;
  memset(&tmpurl, 0, sizeof(tmpurl));
  result = parseurl(url, &tmpurl, flags);
  if(!result) {
    free_urlhandle(u);
    *u = tmpurl;
  }
  return result;
}

CURLU *curl_url(void)
{
  return calloc(1, sizeof(struct Curl_URL));
}
CURLUcode curl_url_set(CURLU *u, CURLUPart what,
                       const char *part, unsigned int flags)
{
  char **storep = NULL;
  bool urlencode = (flags & CURLU_URLENCODE) ? 1 : 0;
  bool plusencode = FALSE;
  bool urlskipslash = FALSE;
  bool leadingslash = FALSE;
  bool appendquery = FALSE;
  bool equalsencode = FALSE;
  size_t nalloc;

  if(!u)
    return CURLUE_BAD_HANDLE;
  if(!part) {
    /* setting a part to NULL clears it */
    switch(what) {
    case CURLUPART_URL:
      break;
    case CURLUPART_SCHEME:
      storep = &u->scheme;
      u->guessed_scheme = FALSE;
      break;
    case CURLUPART_USER:
      storep = &u->user;
      break;
    case CURLUPART_PASSWORD:
      storep = &u->password;
      break;
    case CURLUPART_OPTIONS:
      storep = &u->options;
      break;
    case CURLUPART_HOST:
      storep = &u->host;
      break;
    case CURLUPART_ZONEID:
      storep = &u->zoneid;
      break;
    case CURLUPART_PORT:
      u->portnum = 0;
      storep = &u->port;
      break;
    case CURLUPART_PATH:
      storep = &u->path;
      break;
    case CURLUPART_QUERY:
      storep = &u->query;
      u->query_present = FALSE;
      break;
    case CURLUPART_FRAGMENT:
      storep = &u->fragment;
      u->fragment_present = FALSE;
      break;
    default:
      return CURLUE_UNKNOWN_PART;
    }
    if(storep && *storep) {
      Curl_safefree(*storep);
    }
    else if(!storep) {
      free_urlhandle(u);
      memset(u, 0, sizeof(struct Curl_URL));
    }
    return CURLUE_OK;
  }

  nalloc = strlen(part);
  if(nalloc > CURL_MAX_INPUT_LENGTH)
    /* excessive input length */
    return CURLUE_MALFORMED_INPUT;

  switch(what) {
  case CURLUPART_SCHEME: {
    size_t plen = strlen(part);
    const char *s = part;
    if((plen > MAX_SCHEME_LEN) || (plen < 1))
      /* too long or too short */
      return CURLUE_BAD_SCHEME;
   /* verify that it is a fine scheme */
    if(!(flags & CURLU_NON_SUPPORT_SCHEME) && !Curl_get_scheme_handler(part))
      return CURLUE_UNSUPPORTED_SCHEME;
    storep = &u->scheme;
    urlencode = FALSE; /* never */
    if(ISALPHA(*s)) {
      /* ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
      while(--plen) {
        if(ISALNUM(*s) || (*s == '+') || (*s == '-') || (*s == '.'))
          s++; /* fine */
        else
          return CURLUE_BAD_SCHEME;
      }
    }
    else
      return CURLUE_BAD_SCHEME;
    u->guessed_scheme = FALSE;
    break;
  }
  case CURLUPART_USER:
    storep = &u->user;
    break;
  case CURLUPART_PASSWORD:
    storep = &u->password;
    break;
  case CURLUPART_OPTIONS:
    storep = &u->options;
    break;
  case CURLUPART_HOST:
    storep = &u->host;
    Curl_safefree(u->zoneid);
    break;
  case CURLUPART_ZONEID:
    storep = &u->zoneid;
    break;
  case CURLUPART_PORT:
    if(!ISDIGIT(part[0]))
      /* not a number */
      return CURLUE_BAD_PORT_NUMBER;
    else {
      char *tmp;
      char *endp;
      unsigned long port;
      errno = 0;
      port = strtoul(part, &endp, 10);  /* must be decimal */
      if(errno || (port > 0xffff) || *endp)
        /* weirdly provided number, not good! */
        return CURLUE_BAD_PORT_NUMBER;
      tmp = strdup(part);
      if(!tmp)
        return CURLUE_OUT_OF_MEMORY;
      free(u->port);
      u->port = tmp;
      u->portnum = (unsigned short)port;
      return CURLUE_OK;
    }
  case CURLUPART_PATH:
    urlskipslash = TRUE;
    leadingslash = TRUE; /* enforce */
    storep = &u->path;
    break;
  case CURLUPART_QUERY:
    plusencode = urlencode;
    appendquery = (flags & CURLU_APPENDQUERY) ? 1 : 0;
    equalsencode = appendquery;
    storep = &u->query;
    u->query_present = TRUE;
    break;
  case CURLUPART_FRAGMENT:
    storep = &u->fragment;
    u->fragment_present = TRUE;
    break;
  case CURLUPART_URL: {
    /*
     * Allow a new URL to replace the existing (if any) contents.
     *
     * If the existing contents is enough for a URL, allow a relative URL to
     * replace it.
     */
    CURLcode result;
    CURLUcode uc;
    char *oldurl;
    char *redired_url;

    if(!nalloc)
      /* a blank URL is not a valid URL */
      return CURLUE_MALFORMED_INPUT;

    /* if the new thing is absolute or the old one is not
     * (we could not get an absolute URL in 'oldurl'),
     * then replace the existing with the new. */
    if(Curl_is_absolute_url(part, NULL, 0,
                            flags & (CURLU_GUESS_SCHEME|
                                     CURLU_DEFAULT_SCHEME))
       || curl_url_get(u, CURLUPART_URL, &oldurl, flags)) {
      return parseurl_and_replace(part, u, flags);
    }

    /* apply the relative part to create a new URL
     * and replace the existing one with it. */
    result = concat_url(oldurl, part, &redired_url);
    free(oldurl);
    if(result)
      return cc2cu(result);

    uc = parseurl_and_replace(redired_url, u, flags);
    free(redired_url);
    return uc;
  }
  default:
    return CURLUE_UNKNOWN_PART;
  }
  DEBUGASSERT(storep);
  {
    const char *newp;
    struct dynbuf enc;
    Curl_dyn_init(&enc, nalloc * 3 + 1 + leadingslash);

    if(leadingslash && (part[0] != '/')) {
      CURLcode result = Curl_dyn_addn(&enc, "/", 1);
      if(result)
        return cc2cu(result);
    }
    if(urlencode) {
      const unsigned char *i;

      for(i = (const unsigned char *)part; *i; i++) {
        CURLcode result;
        if((*i == ' ') && plusencode) {
          result = Curl_dyn_addn(&enc, "+", 1);
          if(result)
            return CURLUE_OUT_OF_MEMORY;
        }
        else if(ISUNRESERVED(*i) ||
                ((*i == '/') && urlskipslash) ||
                ((*i == '=') && equalsencode)) {
          if((*i == '=') && equalsencode)
            /* only skip the first equals sign */
            equalsencode = FALSE;
          result = Curl_dyn_addn(&enc, i, 1);
          if(result)
            return cc2cu(result);
        }
        else {
          char out[3]={'%'};
          out[1] = hexdigits[*i >> 4];
          out[2] = hexdigits[*i & 0xf];
          result = Curl_dyn_addn(&enc, out, 3);
          if(result)
            return cc2cu(result);
        }
      }
    }
    else {
      char *p;
      CURLcode result = Curl_dyn_add(&enc, part);
      if(result)
        return cc2cu(result);
      p = Curl_dyn_ptr(&enc);
      while(*p) {
        /* make sure percent encoded are lower case */
        if((*p == '%') && ISXDIGIT(p[1]) && ISXDIGIT(p[2]) &&
           (ISUPPER(p[1]) || ISUPPER(p[2]))) {
          p[1] = Curl_raw_tolower(p[1]);
          p[2] = Curl_raw_tolower(p[2]);
          p += 3;
        }
        else
          p++;
      }
    }
    newp = Curl_dyn_ptr(&enc);

    if(appendquery && newp) {
      /* Append the 'newp' string onto the old query. Add a '&' separator if
         none is present at the end of the existing query already */

      size_t querylen = u->query ? strlen(u->query) : 0;
      bool addamperand = querylen && (u->query[querylen -1] != '&');
      if(querylen) {
        struct dynbuf qbuf;
        Curl_dyn_init(&qbuf, CURL_MAX_INPUT_LENGTH);

        if(Curl_dyn_addn(&qbuf, u->query, querylen)) /* add original query */
          goto nomem;

        if(addamperand) {
          if(Curl_dyn_addn(&qbuf, "&", 1))
            goto nomem;
        }
        if(Curl_dyn_add(&qbuf, newp))
          goto nomem;
        Curl_dyn_free(&enc);
        free(*storep);
        *storep = Curl_dyn_ptr(&qbuf);
        return CURLUE_OK;
nomem:
        Curl_dyn_free(&enc);
        return CURLUE_OUT_OF_MEMORY;
      }
    }

    else if(what == CURLUPART_HOST) {
      size_t n = Curl_dyn_len(&enc);
      if(!n && (flags & CURLU_NO_AUTHORITY)) {
        /* Skip hostname check, it is allowed to be empty. */
      }
      else {
        bool bad = FALSE;
        if(!n)
          bad = TRUE; /* empty hostname is not okay */
        else if(!urlencode) {
          /* if the host name part was not URL encoded here, it was set ready
             URL encoded so we need to decode it to check */
          size_t dlen;
          char *decoded = NULL;
          CURLcode result =
            Curl_urldecode(newp, n, &decoded, &dlen, REJECT_CTRL);
          if(result || hostname_check(u, decoded, dlen))
            bad = TRUE;
          free(decoded);
        }
        else if(hostname_check(u, (char *)newp, n))
          bad = TRUE;
        if(bad) {
          Curl_dyn_free(&enc);
          return CURLUE_BAD_HOSTNAME;
        }
      }
    }

    free(*storep);
    *storep = (char *)newp;
  }
  return CURLUE_OK;
}
#endif
