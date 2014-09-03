/*
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef HW_OFFLOAD_H
#define HW_OFFLOAD_H 1

#include "datapath.h"
#include "flow.h"

int ovs_hw_flow_insert(struct datapath *dp, struct ovs_flow *flow);
int ovs_hw_flow_remove(struct datapath *dp, struct ovs_flow *flow);
int ovs_hw_flow_flush(struct datapath *dp);
void ovs_hw_port_add(struct datapath *dp, struct vport *vport);
void ovs_hw_port_del(struct datapath *dp, struct vport *vport);

#endif
