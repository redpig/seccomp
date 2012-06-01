all: resumption seccomp_bpf_tests

seccomp_bpf_tests: seccomp_bpf_tests.c test_harness.h
	$(CC) seccomp_bpf_tests.c -o seccomp_bpf_tests $(CFLAGS) $(CPPFLAGS) $(LDFLAGS)

resumption: resumption.c test_harness.h
	$(CC) $^ -o $@ $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -ggdb3
