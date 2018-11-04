
#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

// libmonit
#include "util/List.h"

#include "monit.h"
#include "event.h"
#include "ProcessTree.h"
#include "protocol.h"


/* ----------------------------------------------------------------- Private */


/**
 * Escape the JSON string's meta chars C string
 * @param B Output StringBuffer object
 * @param buf String to escape
 */
static void _escapeJSON(StringBuffer_T B, const char *buf) {
        for (int i = 0; buf[i]; i++) {
                if (buf[i] == '\\')
                        StringBuffer_append(B, "\\\\");
                else if (buf[i] == '"')
                        StringBuffer_append(B, "\\\"");
                else
                        StringBuffer_append(B, "%c", buf[i]);
        }
}


/**
 * Prints a document header into the given buffer.
 * @param B StringBuffer object
 * @param V Format version
 * @param myip The client-side IP address
 */
static void json_document_head(StringBuffer_T B, int V, const char *myip) {
        if (V == 2)
                StringBuffer_append(B, "{\"monit\":{\"@id\":\"%s\",\"@incarnation\":%lld,\"@version\":\"%s\",\"server\":{", Run.id, (long long)Run.incarnation, VERSION);
        else
                StringBuffer_append(B,
                                    "{\"monit\":{"
                                    "\"server\":{"
                                    "\"id\":\"%s\","
                                    "\"incarnation\":%lld,"
                                    "\"version\":\"%s\",",
                                    Run.id,
                                    (long long)Run.incarnation,
                                    VERSION);
        StringBuffer_append(B,
                            "\"uptime\":%lld,"
                            "\"poll\":%d,"
                            "\"startdelay\":%d,"
                            "\"localhostname\":\"%s\","
                            "\"controlfile\":\"%s\"",
                            (long long)ProcessTree_getProcessUptime(getpid()),
                            Run.polltime,
                            Run.startdelay,
                            Run.system->name ? Run.system->name : "",
                            Run.files.control ? Run.files.control : "");

        if (Run.httpd.flags & Httpd_Net || Run.httpd.flags & Httpd_Unix) {
                if (Run.httpd.flags & Httpd_Net)
                        StringBuffer_append(B, ",\"httpd\":{\"address\":\"%s\",\"port\":%d,\"ssl\":%d}", Run.httpd.socket.net.address ? Run.httpd.socket.net.address : myip ? myip : "", Run.httpd.socket.net.port, Run.httpd.flags & Httpd_Ssl);
                else if (Run.httpd.flags & Httpd_Unix)
                        StringBuffer_append(B, ",\"httpd\":{\"unixsocket\":\"%s\"}", Run.httpd.socket.unix.path ? Run.httpd.socket.unix.path : "");

                if (Run.mmonitcredentials)
                        StringBuffer_append(B, ",\"credentials\":{\"username\":\"%s\",\"password\":\"%s\"}", Run.mmonitcredentials->uname, Run.mmonitcredentials->passwd);
        }

        StringBuffer_append(B,
                            "}"
                            ",\"platform\":{"
                            "\"name\":\"%s\","
                            "\"release\":\"%s\","
                            "\"version\":\"%s\","
                            "\"machine\":\"%s\","
                            "\"cpu\":%d,"
                            "\"memory\":%llu,"
                            "\"swap\":%llu"
                            "},",
                            systeminfo.uname.sysname,
                            systeminfo.uname.release,
                            systeminfo.uname.version,
                            systeminfo.uname.machine,
                            systeminfo.cpus,
                            (unsigned long long)((double)systeminfo.mem_max / 1024.),   // Send as kB for backward compatibility
                            (unsigned long long)((double)systeminfo.swap_max / 1024.)); // Send as kB for backward compatibility
}


/**
 * Prints a document footer into the given buffer.
 * @param B StringBuffer object
 */
static void json_document_foot(StringBuffer_T B) {
        StringBuffer_append(B, "}}");
}


/**
 * Prints a service status into the given buffer.
 * @param S Service object
 * @param B StringBuffer object
 * @param V Format version
 */
static void json_status_service(Service_T S, StringBuffer_T B, int V) {
        boolean_t comma = false;
        if (V == 2)
                StringBuffer_append(B, "{\"@name\":\"%s\",\"type\":%d,", S->name ? S->name : "", S->type);
        else
                StringBuffer_append(B, "{\"@type\":%d,\"name\":\"%s\",", S->type, S->name ? S->name : "");
        StringBuffer_append(B,
                            "\"collected_sec\":%lld,"
                            "\"collected_usec\":%ld,"
                            "\"status\":%d,"
                            "\"status_hint\":%d,"
                            "\"monitor\":%d,"
                            "\"monitormode\":%d,"
                            "\"onreboot\":%d,"
                            "\"pendingaction\":%d,"
                            "\"depends_on\":[",
                            (long long)S->collected.tv_sec,
                            (long)S->collected.tv_usec,
                            S->error,
                            S->error_hint,
                            S->monitor,
                            S->mode,
                            S->onreboot,
                            S->doaction);
        
        for (Dependant_T d = S->dependantlist; d; d = d->next) {
                if (d->dependant != NULL) {
                        if(comma) StringBuffer_append(B, ",");
                        StringBuffer_append(B, "\"%s\"", d->dependant);
                        comma = true;
                }
        }
        comma = false;
        StringBuffer_append(B, "]");
        
        if (S->every.type != Every_Cycle) {
                StringBuffer_append(B, ",\"every\":{\"type\":%d,", S->every.type);
                if (S->every.type == 1)
                        StringBuffer_append(B, "\"counter\":%d,\"number\":%d", S->every.spec.cycle.counter, S->every.spec.cycle.number);
                else
                        StringBuffer_append(B, "\"cron\":\"%s\"", S->every.spec.cron);
                StringBuffer_append(B, "}");
        }
        if (Util_hasServiceStatus(S)) {
                switch (S->type) {
                        case Service_File:
                                StringBuffer_append(B,
                                        ",\"mode\":%o,"
                                        "\"uid\":%d,"
                                        "\"gid\":%d,"
                                        "\"timestamp\":%lld,"
                                        "\"size\":%llu",
                                        S->inf->priv.file.mode & 07777,
                                        (int)S->inf->priv.file.uid,
                                        (int)S->inf->priv.file.gid,
                                        (long long)S->inf->priv.file.timestamp,
                                        (unsigned long long)S->inf->priv.file.size);
                                if (S->checksum)
                                        StringBuffer_append(B, ",\"checksum\":{\"@type\":\"%s\",\"#text\":\"%s\"}", checksumnames[S->checksum->type], S->inf->priv.file.cs_sum);
                                break;

                        case Service_Directory:
                                StringBuffer_append(B,
                                        ",\"mode\":%o,"
                                        "\"uid\":%d,"
                                        "\"gid\":%d,"
                                        "\"timestamp\":%lld",
                                        S->inf->priv.directory.mode & 07777,
                                        (int)S->inf->priv.directory.uid,
                                        (int)S->inf->priv.directory.gid,
                                        (long long)S->inf->priv.directory.timestamp);
                                break;

                        case Service_Fifo:
                                StringBuffer_append(B,
                                        ",\"mode\":%o,"
                                        "\"uid\":%d,"
                                        "\"gid\":%d,"
                                        "\"timestamp\":%lld",
                                        S->inf->priv.fifo.mode & 07777,
                                        (int)S->inf->priv.fifo.uid,
                                        (int)S->inf->priv.fifo.gid,
                                        (long long)S->inf->priv.fifo.timestamp);
                                break;

                        case Service_Filesystem:
                                StringBuffer_append(B,
                                        ",\"mode\":%o,"
                                        "\"uid\":%d,"
                                        "\"gid\":%d,"
                                        "\"flags\":%d,"
                                        "\"block\":{"
                                        "\"percent\":%.1f,"
                                        "\"usage\":%.1f,"
                                        "\"total\":%.1f"
                                        "}",
                                        S->inf->priv.filesystem.mode & 07777,
                                        (int)S->inf->priv.filesystem.uid,
                                        (int)S->inf->priv.filesystem.gid,
                                        S->inf->priv.filesystem.flags,
                                        S->inf->priv.filesystem.space_percent,
                                        S->inf->priv.filesystem.f_bsize > 0 ? (double)S->inf->priv.filesystem.space_total / 1048576. * (double)S->inf->priv.filesystem.f_bsize : 0.,
                                        S->inf->priv.filesystem.f_bsize > 0 ? (double)S->inf->priv.filesystem.f_blocks / 1048576. * (double)S->inf->priv.filesystem.f_bsize : 0.);
                                if (S->inf->priv.filesystem.f_files > 0) {
                                        StringBuffer_append(B,
                                                ",\"inode\":{"
                                                "\"percent\":%.1f,"
                                                "\"usage\":%lld,"
                                                "\"total\":%lld"
                                                "}",
                                                S->inf->priv.filesystem.inode_percent,
                                                S->inf->priv.filesystem.inode_total,
                                                S->inf->priv.filesystem.f_files);
                                }
                                break;

                        case Service_Net:
                                StringBuffer_append(B,
                                        ",\"link\":{"
                                        "\"state\":%d,"
                                        "\"speed\":%lld,"
                                        "\"duplex\":%d,"
                                        "\"download\":{"
                                        "\"packets\":{"
                                        "\"now\":%lld,"
                                        "\"total\":%lld"
                                        "},"
                                        "\"bytes\":{"
                                        "\"now\":%lld,"
                                        "\"total\":%lld"
                                        "},"
                                        "\"errors\":{"
                                        "\"now\":%lld,"
                                        "\"total\":%lld"
                                        "}"
                                        "},"
                                        "\"upload\":{"
                                        "\"packets\":{"
                                        "\"now\":%lld,"
                                        "\"total\":%lld"
                                        "},"
                                        "\"bytes\":{"
                                        "\"now\":%lld,"
                                        "\"total\":%lld"
                                        "},"
                                        "\"errors\":{"
                                        "\"now\":%lld,"
                                        "\"total\":%lld"
                                        "}"
                                        "}"
                                        "}",
                                        Link_getState(S->inf->priv.net.stats),
                                        Link_getSpeed(S->inf->priv.net.stats),
                                        Link_getDuplex(S->inf->priv.net.stats),
                                        Link_getPacketsInPerSecond(S->inf->priv.net.stats),
                                        Link_getPacketsInTotal(S->inf->priv.net.stats),
                                        Link_getBytesInPerSecond(S->inf->priv.net.stats),
                                        Link_getBytesInTotal(S->inf->priv.net.stats),
                                        Link_getErrorsInPerSecond(S->inf->priv.net.stats),
                                        Link_getErrorsInTotal(S->inf->priv.net.stats),
                                        Link_getPacketsOutPerSecond(S->inf->priv.net.stats),
                                        Link_getPacketsOutTotal(S->inf->priv.net.stats),
                                        Link_getBytesOutPerSecond(S->inf->priv.net.stats),
                                        Link_getBytesOutTotal(S->inf->priv.net.stats),
                                        Link_getErrorsOutPerSecond(S->inf->priv.net.stats),
                                        Link_getErrorsOutTotal(S->inf->priv.net.stats));
                                break;

                        case Service_Process:
                                StringBuffer_append(B,
                                        ",\"pid\":%d,"
                                        "\"ppid\":%d,"
                                        "\"uid\":%d,"
                                        "\"euid\":%d,"
                                        "\"gid\":%d,"
                                        "\"uptime\":%lld",
                                        S->inf->priv.process.pid,
                                        S->inf->priv.process.ppid,
                                        S->inf->priv.process.uid,
                                        S->inf->priv.process.euid,
                                        S->inf->priv.process.gid,
                                        (long long)S->inf->priv.process.uptime);
                                if (Run.flags & Run_ProcessEngineEnabled) {
                                        StringBuffer_append(B,
                                                ",\"threads\":%d,"
                                                "\"children\":%d,"
                                                "\"memory\":{"
                                                "\"percent\":%.1f,"
                                                "\"percenttotal\":%.1f,"
                                                "\"kilobyte\":%llu,"
                                                "\"kilobytetotal\":%llu"
                                                "},"
                                                "\"cpu\":{"
                                                "\"percent\":%.1f,"
                                                "\"percenttotal\":%.1f"
                                                "}",
                                                S->inf->priv.process.threads,
                                                S->inf->priv.process.children,
                                                S->inf->priv.process.mem_percent,
                                                S->inf->priv.process.total_mem_percent,
                                                (unsigned long long)((double)S->inf->priv.process.mem / 1024.),       // Send as kB for backward compatibility
                                                (unsigned long long)((double)S->inf->priv.process.total_mem / 1024.), // Send as kB for backward compatibility
                                                S->inf->priv.process.cpu_percent,
                                                S->inf->priv.process.total_cpu_percent);
                                }
                                break;

                        default:
                                break;
                }
                StringBuffer_append(B, ",\"icmp\":[");
                for (Icmp_T i = S->icmplist; i; i = i->next) {
                        if(comma) StringBuffer_append(B, ",");
                        StringBuffer_append(B,
                                            "{"
                                            "\"type\":\"%s\","
                                            "\"responsetime\":%.6f"
                                            "}",
                                            icmpnames[i->type],
                                            i->is_available == Connection_Ok ? i->response / 1000. : -1.); // We send the response time in [s] for backward compatibility (with microseconds precision)
                        comma = true;
                }
                StringBuffer_append(B, "]");
                comma = false;
                StringBuffer_append(B, ",\"port\":[");
                for (Port_T p = S->portlist; p; p = p->next) {
                        if(comma) StringBuffer_append(B, ",");
                        StringBuffer_append(B,
                                            "{"
                                            "\"hostname\":\"%s\","
                                            "\"portnumber\":%d,"
                                            "\"request\":\"",
                                            p->hostname ? p->hostname : "",
                                            p->target.net.port);
                        _escapeJSON(B, Util_portRequestDescription(p));
                        StringBuffer_append(B, "\","
                                            "\"protocol\":\"%s\","
                                            "\"type\":\"%s\","
                                            "\"responsetime\":%.6f"
                                            "}",
                                            p->protocol->name ? p->protocol->name : "",
                                            Util_portTypeDescription(p),
                                            p->is_available == Connection_Ok ? p->response / 1000. : -1.); // We send the response time in [s] for backward compatibility (with microseconds precision)
                        comma = true;
                }
                StringBuffer_append(B, "]");
                comma = false;
                StringBuffer_append(B, ",\"unix\":[");
                for (Port_T p = S->socketlist; p; p = p->next) {
                        if(comma) StringBuffer_append(B, ",");
                        StringBuffer_append(B,
                                            "{"
                                            "\"path\":\"%s\","
                                            "\"protocol\":\"%s\","
                                            "\"responsetime\":%.6f"
                                            "}",
                                            p->target.unix.pathname ? p->target.unix.pathname : "",
                                            p->protocol->name ? p->protocol->name : "",
                                            p->is_available == Connection_Ok ? p->response / 1000. : -1.); // We send the response time in [s] for backward compatibility (with microseconds precision)
                        comma = true;
                }
                StringBuffer_append(B, "]");
                if (S->type == Service_System && (Run.flags & Run_ProcessEngineEnabled)) {
                        StringBuffer_append(B,
                                            ",\"system\":{"
                                            "\"load\":{"
                                            "\"avg01\":%.2f,"
                                            "\"avg05\":%.2f,"
                                            "\"avg15\":%.2f"
                                            "},"
                                            "\"cpu\":{"
                                            "\"user\":%.1f,"
                                            "\"system\":%.1f"
#ifdef HAVE_CPU_WAIT
                                            ",\"wait\":%.1f"
#endif
                                            "},"
                                            "\"memory\":{"
                                            "\"percent\":%.1f,"
                                            "\"kilobyte\":%llu"
                                            "},"
                                            "\"swap\":{"
                                            "\"percent\":%.1f,"
                                            "\"kilobyte\":%llu"
                                            "}"
                                            "}",
                                            systeminfo.loadavg[0],
                                            systeminfo.loadavg[1],
                                            systeminfo.loadavg[2],
                                            systeminfo.total_cpu_user_percent > 0. ? systeminfo.total_cpu_user_percent : 0.,
                                            systeminfo.total_cpu_syst_percent > 0. ? systeminfo.total_cpu_syst_percent : 0.,
#ifdef HAVE_CPU_WAIT
                                            systeminfo.total_cpu_wait_percent > 0. ? systeminfo.total_cpu_wait_percent : 0.,
#endif
                                            systeminfo.total_mem_percent,
                                            (unsigned long long)((double)systeminfo.total_mem / 1024.),               // Send as kB for backward compatibility
                                            systeminfo.total_swap_percent,
                                            (unsigned long long)((double)systeminfo.total_swap / 1024.));             // Send as kB for backward compatibility
                }
                if (S->type == Service_Program && S->program->started) {
                        StringBuffer_append(B,
                                            ",\"program\":{"
                                            "\"started\":%lld,"
                                            "\"status\":%d,"
                                            "\"output\":\"",
                                            (long long)S->program->started,
                                            S->program->exitStatus);
                        _escapeJSON(B, StringBuffer_toString(S->program->output));
                        StringBuffer_append(B,
                                            "\""
                                            "}");
                }
        }
        StringBuffer_append(B, "}");
}


/**
 * Prints a servicegroups into the given buffer.
 * @param SG ServiceGroup object
 * @param B StringBuffer object
 */
static void json_status_servicegroup(ServiceGroup_T SG, StringBuffer_T B) {
        boolean_t comma = false;
        StringBuffer_append(B, "{\"@name\":\"%s\",\"service\":[", SG->name);
        for (list_t m = SG->members->head; m; m = m->next) {
                Service_T s = m->e;
                if(comma) StringBuffer_append(B, ",");
                StringBuffer_append(B, "\"%s\"", s->name);
                comma = true;
        }
        StringBuffer_append(B, "]}");
}


/**
 * Prints a event description into the given buffer.
 * @param E Event object
 * @param B StringBuffer object
 */
static void json_status_event(Event_T E, StringBuffer_T B) {
        StringBuffer_append(B,
                            "\"event\":{"
                            "\"collected_sec\":%lld,"
                            "\"collected_usec\":%ld,"
                            "\"service\":\"%s\","
                            "\"type\":%d,"
                            "\"id\":%ld,"
                            "\"state\":%d,"
                            "\"action\":%d,"
                            "\"message\":\"",
                            (long long)E->collected.tv_sec,
                            (long)E->collected.tv_usec,
                            E->id == Event_Instance ? "Monit" : E->source->name,
                            E->type,
                            E->id,
                            E->state,
                            Event_get_action(E));
        _escapeJSON(B, E->message);
        StringBuffer_append(B, "\"");
        if (E->source->token)
                StringBuffer_append(B, ",\"token\":\"%s\"", E->source->token);
        StringBuffer_append(B, "}");
}


/* ------------------------------------------------------------------ Public */


/**
 * Get a JSON formated message for event notification or general status
 * of monitored services and resources.
 * @param E An event object or NULL for general status
 * @param V Format version
 * @param myip The client-side IP address
 */
void status_json(StringBuffer_T B, Event_T E, int V, const char *myip) {
        Service_T S;
        ServiceGroup_T SG;
        boolean_t comma = false;

        json_document_head(B, V, myip);
        if (V == 2)
                StringBuffer_append(B, "\"services\":{");
        StringBuffer_append(B, "\"service\":[");
        for (S = servicelist_conf; S; S = S->next_conf) {
                if(comma) StringBuffer_append(B, ",");
                json_status_service(S, B, V);
                comma = true;
        }
        StringBuffer_append(B, "]");
        if (V == 2) {
                StringBuffer_append(B, "},\"servicegroups\":{\"servicegroup\":[");
                comma = false;
                for (SG = servicegrouplist; SG; SG = SG->next) {
                        if(comma) StringBuffer_append(B, ",");
                        json_status_servicegroup(SG, B);
                        comma = true;
                }
                StringBuffer_append(B, "]}");
        }
        if (E)
                json_status_event(E, B);
        json_document_foot(B);
}

