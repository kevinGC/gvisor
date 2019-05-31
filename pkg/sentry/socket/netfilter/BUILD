package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "netfilter",
    srcs = [
        "netfilter.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netfilter",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/iptables",
        "//pkg/tcpip/stack",
    ],
)
