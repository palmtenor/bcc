#!/usr/bin/python
#
# cache_miss.py Example of using BPF perf event.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# Copyright (c) 2016 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 18-Oct-2016    Teng Qin    Created this.

from __future__ import print_function
import argparse
from bcc import BPF, BPFPerfType, BPFPerfHWConfig
import signal
from time import sleep

parser = argparse.ArgumentParser(
    description="Summarize cache misses by PID or stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument(
    "--duration", default=10, type=int, help="Time to run, in seconds")
parser.add_argument(
    "--sample_period", default=0, type=int,
    help="Sample one in this many events")
parser.add_argument(
    "--sample_freq", default=0, type=int,
    help="Try to sample this many events per second")
parser.add_argument(
    "--stack", default=False, action="store_true",
    help="Summarize and output stack traces")
opts = parser.parse_args()

if opts.stack:
    DATA = """
    int kernstack;
    int userstack;"""
    HASH = "BPF_STACK_TRACE(stack_traces, 65535);"
    GET = """
    key.kernstack = stack_traces.get_stackid(ctx, KERN_STACK);
    key.userstack = stack_traces.get_stackid(ctx, USER_STACK);"""
else:
    DATA = ""
    HASH = ""
    GET = ""

# load BPF program
text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define KERN_STACK BPF_F_REUSE_STACKID
#define USER_STACK BPF_F_REUSE_STACKID | BPF_F_USER_STACK

struct key_t {
    char name[TASK_COMM_LEN];
    int pid;
    int cpu;
    DATA_REPLACE
};

BPF_HASH(count, struct key_t);
HASH_REPLACE

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&key.name, sizeof(key.name));
    GET_REPLACE

    u64 zero = 0, *val;
    val = count.lookup_or_init(&key, &zero);
    (*val) += ctx->sample_period;

    return 0;
}
"""
text = text.replace("DATA_REPLACE", DATA)
text = text.replace("HASH_REPLACE", HASH)
text = text.replace("GET_REPLACE", GET)
b = BPF(text=text)

b.attach_perf_event(
    ev_type=BPFPerfType.HARDWARE, ev_config=BPFPerfHWConfig.CACHE_MISSES,
    fn_name="on_cache_miss", sample_period = opts.sample_period,
    sample_freq = opts.sample_freq)

print("Running for {} seconds or hit Ctrl-C to end.".format(opts.duration))

try:
    sleep(opts.duration)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, lambda signal, frame: print())

count = b.get_table('count')
if opts.stack:
    stack_traces = b.get_table("stack_traces")

for k, v in sorted(count.items(), key=lambda count: count[1].value):
    print('PID {}-{} on CPU {}: {} cache misses'.format(
        k.pid, k.name, k.cpu, v.value))
    if not opts.stack:
        continue
    print("  Kernel Stack:")
    if k.kernstack < 0:
        print("    {}".format(k.kernstack))
    else:
        kernstack = list(stack_traces.walk(k.kernstack))
        for addr in kernstack:
            print("    {:016x} {:s}".format(addr, b.ksym(addr)))
    print("  User Stack:")
    if k.userstack < 0:
        print("    {}".format(k.userstack))
    else:
        try:
            userstack = list(stack_traces.walk(k.userstack))
        except Exception:
            continue
        for addr in userstack:
            print("    {:016x} {:s}".format(addr, b.sym(addr, k.pid)))
    print()
