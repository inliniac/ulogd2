#ifndef _PRINTFLOW_H
#define _PRINTFLOW_H

#define FLOW_IDS 17
extern struct ulogd_key printflow_keys[FLOW_IDS];

int printflow_print(struct ulogd_key *res, char *buf);

#endif
