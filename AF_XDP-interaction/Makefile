# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

# USER_TARGETS   := af_xdp_user
# USER_TARGETS   += btf_unit_test
USER_TARGETS   := ids
USER_TARGETS   += test_snort_user
BPF_TARGETS    := af_xdp_kern
BPF_TARGETS    += test_snort_kern
BPF_TARGETS    += btf_unit_test_bpf

# Define C-code objects USER_TARGETS needs
USER_TARGETS_OBJS := common_params.o common_user_bpf_xdp.o
USER_TARGETS_OBJS += hashmap.o lib_xsk_extend.o
# USER_TARGETS_OBJS += lib_xsk_extend.o
USER_TARGETS_OBJS += ethtool_utils.o
USER_TARGETS_OBJS += rule.o
USER_TARGETS_OBJS += btf.o
USER_TARGETS_OBJS += xsk_socket.o
USER_TARGETS_OBJS += aho-corasick.o
USER_TARGETS_OBJS += str2dfa.o

# The USER_TARGETS_OBJS have a dependency of this header file
USER_TARGETS_OBJS_DEPS += common_defines.h

LDLIBS     += -lpthread
LDLIBS     += -lrt

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
