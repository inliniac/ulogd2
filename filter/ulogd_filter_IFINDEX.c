#include <stdio.h>
#include <stdlib.h>
#include <ulogd/ulogd.h>

static struct ulogd_key ifindex_keys[] = {
	{ 
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.in", 
	},
	{ 
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.out", 
	},
};

static struct ulogd_key ifindex_inp[] = {
	{ 
		.type = ULOGD_RET_UINT32,
		.name = "oob.ifindex_in", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.ifindex_out",
	},
};

static int interp_ifindex(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output;

	ret[0].u.value.ptr = "eth_in_FIXME";
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ptr = "eth_out_FIXME";
	ret[1].flags |= ULOGD_RETF_VALID;

	return 0;
}


static int ifindex_start(struct ulogd_pluginstance *upi)
{
	return 0;
}

static int ifindex_fini(struct ulogd_pluginstance *upi)
{
	return 0;
}

static struct ulogd_plugin ifindex_plugin = {
	.name = "IFINDEX",
	.input = {
		.keys = ifindex_inp,
		.num_keys = ARRAY_SIZE(ifindex_inp),
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = ifindex_keys,
		.num_keys = ARRAY_SIZE(ifindex_keys),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &interp_ifindex,

	.start = &ifindex_start,
	.stop = &ifindex_fini,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ifindex_plugin);
}
