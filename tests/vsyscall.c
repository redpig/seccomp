/* seccomp_bpf_tests.c
 * Copyright (c) 2014 Andy Lutomirski. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test code for seccomp bpf.
 */

#include <asm/siginfo.h>
#define __have_siginfo_t 1
#define __have_sigval_t 1
#define __have_sigevent_t 1

#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <asm/errno.h>
#include <sys/reg.h>
#define __USE_GNU 1
#include <sys/ucontext.h>
#include <sys/mman.h>

#include "test_harness.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#endif

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP	7
#define PTRACE_O_TRACESECCOMP	(1 << PTRACE_EVENT_SECCOMP)
#endif

extern char vgetcpu_entry, vgetcpu_exit;

// Gross hack
static struct __test_metadata *_global_metadata;
#define SET_META() do { _global_metadata = _metadata; } while (0)
#define GET_META() struct __test_metadata *_metadata = _global_metadata

__attribute__((noinline)) static long do_real_getcpu(unsigned *cpu, unsigned *node, void *tcache)
{
	unsigned long rax = __NR_getcpu;
	asm volatile (
		"syscall"
		: "+a" (rax)
		: "D" (cpu),
		  "S" (node),
		  "d" (tcache)
		: "rcx", "r8", "r9", "r10", "r11", "flags");

	return (long)rax;
}

__attribute__((noinline)) static long do_vgetcpu(unsigned *cpu, unsigned *node, void *tcache)
{
#ifdef FORCE_NATIVE
	return do_real_getcpu(cpu, node, tcache);
#endif

	unsigned long old_sp, new_sp;
	unsigned long rax = 0xffffffffff600800;
	asm volatile (
		"mov %%rsp, %[old_sp]\n\t"
		"vgetcpu_entry:\n\t"
		"call *%%rax\n"
		"vgetcpu_exit:\n\t"
		"mov %%rsp, %[new_sp]"
		: [old_sp] "=rm" (old_sp),
		  [new_sp] "=rm" (new_sp),
		  "+a" (rax)
		: "D" (cpu),
		  "S" (node),
		  "d" (tcache)
		: "rcx", "r8", "r9", "r10", "r11");

	if (old_sp != new_sp)
		_exit(1);

	return (long)rax;
}

FIXTURE_DATA(VSYS) {
};

FIXTURE_SETUP(VSYS) {
}

void set_filter(long action)
{
	int ret;

	struct sock_fprog prog;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		         offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_getcpu, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, action)
	};
	memset(&prog, 0, sizeof(prog));
	prog.filter = malloc(sizeof(filter));
	memcpy(prog.filter, filter, sizeof(filter));
	prog.len = (unsigned short)(sizeof(filter)/sizeof(filter[0]));

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (ret)
		_exit(1);
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	if (ret)
		_exit(1);

	free(prog.filter);
}

FIXTURE_TEARDOWN(VSYS) {
};


TEST_F(VSYS, allow) {
	set_filter(SECCOMP_RET_ALLOW);
	ASSERT_EQ(0, do_vgetcpu(0, 0, 0));
}

TEST_F(VSYS, errno) {
	unsigned x = 999;
	set_filter(SECCOMP_RET_ERRNO | 9999);
	ASSERT_EQ(-9999, do_vgetcpu(&x, 0, 0));
	ASSERT_EQ(999, x);
}

static int is_quirky_vsys(unsigned long addr)
{
	return (addr & ~0xC00UL) == 0xFFFFFFFFFF600000UL;
}

struct arch_sigsys {
	void *_call_addr; /* calling user insn */
	int _syscall;	/* triggering system call number */
	unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
};

static int segv_if_no_quirk = 0;
static void TRAP_action(int nr, siginfo_t *info, void *void_context)
{
	GET_META();
	ucontext_t *ctx = (ucontext_t *)void_context;
	char buf[256];
	int len;
	int do_ret = 1;
	struct arch_sigsys *sys = (struct arch_sigsys *)
#ifdef si_syscall
		&(info->si_call_addr);
#else
		&(info->si_pid);
#endif
	unsigned long rip = ctx->uc_mcontext.gregs[REG_RIP];

	ASSERT_EQ(42, info->si_errno);

	if (is_quirky_vsys((unsigned long)sys->_call_addr)) {
#ifdef FORCE_NATIVE
		ASSERT_FALSE(1);
#else
		ASSERT_EQ((unsigned long)&vgetcpu_exit, rip);
#endif
	} else {
		ASSERT_LE(rip - (unsigned long)sys->_call_addr, 15);
		if (segv_if_no_quirk)
			*(char*)0=0;
	}

	_exit(0);
}

static void install_TRAP()
{
	GET_META();

	struct sigaction act;
	pid_t pid;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);
	ASSERT_EQ(0, sigprocmask(SIG_UNBLOCK, &mask, NULL));

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &TRAP_action;
	act.sa_flags = SA_SIGINFO;
	ASSERT_EQ(0, sigaction(SIGSYS, &act, NULL));
}

TEST_F(VSYS, sigsys_vsys) {
	SET_META();

	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		install_TRAP();
		set_filter(SECCOMP_RET_TRAP | 42);
		do_vgetcpu(&x, 0, 0);
		_exit(1);
	} else {
		int status;
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(0, WEXITSTATUS(status));
	}
}

// This isn't really guaranteed.
/*
TEST_F(VSYS, sigsys_segv_high_addr) {
	SET_META();

	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		segv_if_no_quirk = 1;
		install_TRAP();
		set_filter(SECCOMP_RET_TRAP | 42);
		do_vgetcpu((void*)~1UL, 0, 0);
		_exit(1);
	} else {
		int status;
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_EQ(SIGSEGV, WTERMSIG(status));
	}
}
*/

TEST_F(VSYS, sigsys_syscall) {
	SET_META();

	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		install_TRAP();
		set_filter(SECCOMP_RET_TRAP | 42);
		syscall(__NR_getcpu, &x, 0, 0);
		_exit(1);
	} else {
		int status;
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(0, WEXITSTATUS(status));
	}
}

static void wait_stop(pid_t chld)
{
	GET_META();
	int status;
	ASSERT_TRUE(waitpid(chld, &status, 0) == chld && WIFSTOPPED(status));
}

static siginfo_t wait_trap(pid_t chld)
{
	GET_META();
	siginfo_t si;
	ASSERT_EQ(0, waitid(P_PID, chld, &si, WEXITED|WSTOPPED));
	ASSERT_EQ(chld, si.si_pid);
	ASSERT_EQ(CLD_TRAPPED, si.si_code);
	return si;
}

static long get_nr(pid_t chld)
{
	return ptrace(PTRACE_PEEKUSER, chld, 8*ORIG_RAX, 0);
}

static void set_nr(pid_t chld, long nr)
{
	GET_META();
	ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, chld, 8*ORIG_RAX, nr));
}

static void set_ret(pid_t chld, long ret)
{
	GET_META();
	ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, chld, 8*RAX, ret));
}

TEST_F(VSYS, trace_cont) {
	SET_META();

	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		ASSERT_EQ(0, ptrace(PTRACE_TRACEME, 0, 0, 0));
		raise(SIGSTOP);
		set_filter(SECCOMP_RET_TRACE | 42);
		do_vgetcpu(&x, 0, 0);
		ASSERT_NE(999, x);
		_exit(0);
	} else {
		siginfo_t si;
		int status;

		/* Wait for SIGSTOP and enable seccomp tracing. */
		wait_stop(chld);
		ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACESECCOMP));
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Catch the trace event. */
		si = wait_trap(chld);
		ASSERT_EQ(SIGTRAP | (PTRACE_EVENT_SECCOMP << 8), si.si_status);

		/* Continue (i.e. run the syscall). */
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Assert clean exit. */
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(0, WEXITSTATUS(status));
	}
}

TEST_F(VSYS, trace_skip) {
	SET_META();

	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		ASSERT_EQ(0, ptrace(PTRACE_TRACEME, 0, 0, 0));
		raise(SIGSTOP);
		set_filter(SECCOMP_RET_TRACE | 42);
		ASSERT_EQ(-ENOSYS, do_vgetcpu(&x, 0, 0));
		ASSERT_EQ(x, 999);
		_exit(0);
	} else {
		siginfo_t si;
		int status;

		/* Wait for SIGSTOP and enable seccomp tracing. */
		wait_stop(chld);
		ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACESECCOMP));
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Catch the trace event. */
		si = wait_trap(chld);
		ASSERT_EQ(SIGTRAP | (PTRACE_EVENT_SECCOMP << 8), si.si_status);

		/* Cancel the syscall. */
		set_nr(chld, (int)-1);
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Assert clean exit. */
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(0, WEXITSTATUS(status));
	}
}

TEST_F(VSYS, trace_changenr) {
	SET_META();

	pid_t chld = fork();
	if (!chld) {
		long ret;
		ASSERT_EQ(0, ptrace(PTRACE_TRACEME, 0, 0, 0));
		raise(SIGSTOP);
		set_filter(SECCOMP_RET_TRACE | 42);
		ret = do_vgetcpu(0, 0, 0); /* or SIGSYS death */

		/* native mode gets here */
		ASSERT_TRUE(ret == -ENOSYS || ret == -EFAULT);
		_exit(0);
	} else {
		siginfo_t si;
		int status;

		/* Wait for SIGSTOP and enable seccomp tracing. */
		wait_stop(chld);
		ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACESECCOMP));
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Catch the trace event. */
		si = wait_trap(chld);
		ASSERT_EQ(SIGTRAP | (PTRACE_EVENT_SECCOMP << 8), si.si_status);

		/* Change the nr and try to return a bogosity. */
		set_nr(chld, __NR_pipe);
		set_ret(chld, (long)-42);
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Assert sigsys or clean exit. */
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return;  /* non-quirk mode */
		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_EQ(SIGSYS, WTERMSIG(status));
	}
}

/* Tests an absurd condition. Nothing should exercise this. */
TEST_F(VSYS, trace_changenr_high) {
	SET_META();

	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		ASSERT_EQ(0, ptrace(PTRACE_TRACEME, 0, 0, 0));
		raise(SIGSTOP);
		set_filter(SECCOMP_RET_TRACE | 42);
		ASSERT_EQ(-ENOSYS, do_vgetcpu(&x, 0, 0));
		ASSERT_EQ(x, 999);
		_exit(0);
	} else {
		siginfo_t si;
		int status;

		/* Wait for SIGSTOP and enable seccomp tracing. */
		wait_stop(chld);
		ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACESECCOMP));
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Catch the trace event. */
		si = wait_trap(chld);
		ASSERT_EQ(SIGTRAP | (PTRACE_EVENT_SECCOMP << 8), si.si_status);

		/* Cancel the syscall using a high number. */
		set_nr(chld, (int)99999);
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Assert sigsys or clean exit. */
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return;  /* non-quirk mode */
		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_EQ(SIGSYS, WTERMSIG(status));
	}
}

TEST_F(VSYS, trace_notracer) {
	SET_META();
	set_filter(SECCOMP_RET_TRACE | 42);
	ASSERT_EQ(-ENOSYS, do_vgetcpu(0, 0, 0));
}

static void test_return_skip(int nr, long ret)
{
	GET_META();
	unsigned x = 999;
	pid_t chld = fork();
	if (!chld) {
		ASSERT_EQ(0, ptrace(PTRACE_TRACEME, 0, 0, 0));
		raise(SIGSTOP);
		set_filter(SECCOMP_RET_TRACE | 42);
		ASSERT_EQ((nr < 0 ? ret : -ENOSYS), do_vgetcpu(&x, 0, 0));
		ASSERT_EQ(x, 999);
		_exit(0);
	} else {
		siginfo_t si;
		int status;

		/* Wait for SIGSTOP and enable seccomp tracing. */
		wait_stop(chld);
		ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACESECCOMP));
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Catch the trace event. */
		si = wait_trap(chld);
		ASSERT_EQ(SIGTRAP | (PTRACE_EVENT_SECCOMP << 8), si.si_status);

		/* Cancel the syscall and return ret. */
		set_nr(chld, nr);
		set_ret(chld, ret);
		ASSERT_EQ(0, ptrace(PTRACE_CONT, chld, 0, 0));

		/* Assert clean exit. */
		ASSERT_EQ(chld, waitpid(chld, &status, 0));
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(0, WEXITSTATUS(status));
	}

}

TEST_F(VSYS, trace_return_normal) {
	SET_META();
	test_return_skip(-1, -9999);
}

TEST_HARNESS_MAIN
