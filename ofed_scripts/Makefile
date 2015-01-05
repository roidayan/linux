EXTRA_CFLAGS += $(OPENIB_KERNEL_EXTRA_CFLAGS) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		-I$(CWD)/include \
		-I$(CWD)/drivers/infiniband/ulp/ipoib$(CONFIG_IPOIB_VERSION) \
		-I$(CWD)/drivers/infiniband/debug \
		-I$(CWD)/drivers/net/ethernet/chelsio/cxgb3 \
		-I$(CWD)/drivers/net/ethernet/chelsio/cxgb4 \
		-I$(CWD)/net/rds \
		-I$(CWD)/net/eipoib \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlx4 \
		-I$(CWD)/drivers/net/ethernet/mellanox/mlx5/core \
		-I$(CWD)/drivers/infiniband/hw/mlx4 \
		-I$(CWD)/drivers/infiniband/hw/mlx5 \

obj-y := compat$(CONFIG_COMPAT_VERSION)/
obj-$(CONFIG_INFINIBAND)        += drivers/infiniband/
obj-$(CONFIG_CHELSIO_T3)        += drivers/net/ethernet/chelsio/cxgb3/
obj-$(CONFIG_CHELSIO_T4)        += drivers/net/ethernet/chelsio/cxgb4/
obj-$(CONFIG_MLX4_CORE)         += drivers/net/ethernet/mellanox/mlx4/
obj-$(CONFIG_MLX5_CORE)         += drivers/net/ethernet/mellanox/mlx5/core/
obj-$(CONFIG_MLX4_VNIC)         += drivers/net/ethernet/mellanox/mlx4_vnic/
obj-$(CONFIG_RDS)               += net/rds/
obj-$(CONFIG_E_IPOIB)           += drivers/net/eipoib/
obj-$(CONFIG_MEMTRACK)          += drivers/infiniband/debug/
obj-$(CONFIG_SUNRPC_XPRT_RDMA)  += net/sunrpc/xprtrdma/
obj-$(CONFIG_NET_9P_RDMA) += net/9p/
obj-$(CONFIG_9P_FS) += fs/9p/
obj-$(CONFIG_SCSI_CXGB3_ISCSI)  += drivers/scsi/cxgbi/
obj-$(CONFIG_SCSI_CXGB4_ISCSI)  += drivers/scsi/cxgbi/
obj-$(CONFIG_SCSI_SRP_ATTRS)    += drivers/scsi/
