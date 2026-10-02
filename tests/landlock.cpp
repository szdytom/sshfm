/* Test the actual server policy and file operations in a disposable child. */
#define main sshfm_server_main
#include "../src/sshfm.cpp"
#undef main

#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <cstddef>
#include <filesystem>

static void check(bool ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s (errno=%d: %s)\n", what, errno, strerror(errno));
		exit(1);
	}
}

static void denied(int rc, const char *what)
{
	check(rc == -1 && errno == EACCES, what);
}

static void wait_ok(pid_t child)
{
	int status = 0;
	check(waitpid(child, &status, 0) == child, "waitpid");
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child result");
}

int main()
{
	char tmp[] = "/tmp/sshfm-landlock-test-XXXXXX";
	check(mkdtemp(tmp) != nullptr, "temporary directory");
	std::string base = tmp, root = base + "/data", outside = base + "/outside";
	check(mkdir(root.c_str(), 0700) == 0, "data directory");
	check(write_file(outside, "secret"), "outside fixture");
	check(symlink(outside.c_str(), (root + "/1escape").c_str()) == 0, "symlink fixture");

	/* Missing/disabled Landlock must return failure, never silently succeed. */
	for (int error : {ENOSYS, EOPNOTSUPP, EPERM}) {
		pid_t child = fork();
		check(child >= 0, "failure-test fork");
		if (child == 0) {
			struct sock_filter filter[] = {
				BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
				BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_landlock_create_ruleset, 0, 1),
				BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)error),
				BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			};
			struct sock_fprog program = {4, filter};
			check(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "test no_new_privs");
			check(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0, "test filter");
			check(!restrict_server(root), "unavailable Landlock fails closed");
			_exit(0);
		}
		wait_ok(child);
	}

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	check(listener >= 0, "listener socket");
	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	check(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0, "listener bind");
	check(listen(listener, 1) == 0, "listener listen");
	socklen_t addr_size = sizeof(addr);
	check(getsockname(listener, (struct sockaddr *)&addr, &addr_size) == 0, "listener address");
	int ready[2];
	check(pipe(ready) == 0, "ready pipe");
	pid_t child = fork();
	check(child >= 0, "policy-test fork");
	if (child == 0) {
		close(ready[0]);
		check(!restrict_server(base + "/missing"), "missing root fails closed");
		check(!restrict_server(outside), "non-directory root fails closed");
		int abi = (int)syscall(SYS_landlock_create_ruleset, nullptr, 0,
		                       LANDLOCK_CREATE_RULESET_VERSION);
		check(restrict_server(root), "server sandbox");
		check(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs enabled");

		Sandbox sb(root);
		check(sb.create_file("folder", "test", true), "create folder and metadata");
		check(sb.create_file("file", "test", false), "create file and metadata");
		check(sb.save_content("file", "hello", "test"), "atomic save");
		check(sb.rename_entry("file", "folder/moved", "test"), "cross-directory move");
		std::string data;
		check(sb.read_content("folder/moved", data) && data == "hello", "read moved file");
		std::vector<Entry> entries;
		check(sb.list("folder", entries) && entries.size() == 1, "list folder");
		check(truncate(sb.abs("folder/moved").c_str(), 2) == 0, "truncate inside root");

		denied(open(outside.c_str(), O_RDONLY), "outside read");
		denied(open(outside.c_str(), O_WRONLY | O_TRUNC), "outside write");
		denied(truncate(outside.c_str(), 0), "outside truncate");
		denied(open((base + "/new").c_str(), O_CREAT | O_WRONLY, 0600), "outside create");
		denied(unlink(outside.c_str()), "outside unlink");
		denied(open((root + "/1escape").c_str(), O_RDONLY), "symlink escape read");
		denied(truncate((root + "/1escape").c_str(), 0), "symlink escape truncate");
		denied(rename(sb.abs("folder/moved").c_str(), (base + "/moved").c_str()), "move outside");
		denied(symlink(outside.c_str(), (root + "/link").c_str()), "symlink creation");
		denied(mkfifo((root + "/fifo").c_str(), 0600), "FIFO creation");
		check(write_file(root + "/script", "#!/bin/sh\nexit 0\n"), "script fixture");
		check(chmod((root + "/script").c_str(), 0700) == 0, "script mode");
		char *args[] = {const_cast<char *>("script"), nullptr};
		char *env[] = {nullptr};
		denied(execve((root + "/script").c_str(), args, env), "execution inside root");

		std::thread([&] {
			denied(open(outside.c_str(), O_RDONLY), "thread inherits sandbox");
			check(sb.read_content("folder/moved", data) && data == "he", "thread allowed read");
		}).join();
		check(sb.remove_entry("folder", "test") == 1, "recursive delete");

#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
		if (abi >= 4) {
			int fd = socket(AF_INET, SOCK_STREAM, 0);
			check(fd >= 0, "restricted socket");
			denied(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), "outbound TCP");
			struct sockaddr_in new_addr = addr;
			new_addr.sin_port = 0;
			denied(bind(fd, (struct sockaddr *)&new_addr, sizeof(new_addr)), "new TCP bind");
			close(fd);
		}
#endif
		check(write(ready[1], "R", 1) == 1, "signal listener ready");
		int client = accept(listener, nullptr, nullptr);
		check(client >= 0, "accept inherited listener");
		check(write(client, "OK", 2) == 2, "reply through accepted socket");
		close(client);
		_exit(0);
	}
	close(ready[1]);
	close(listener);
	char signal;
	check(read(ready[0], &signal, 1) == 1, "wait for listener");
	close(ready[0]);
	int client = socket(AF_INET, SOCK_STREAM, 0);
	check(client >= 0, "client socket");
	check(connect(client, (struct sockaddr *)&addr, sizeof(addr)) == 0, "connect to sandbox listener");
	char reply[2];
	check(recv(client, reply, 2, MSG_WAITALL) == 2 && memcmp(reply, "OK", 2) == 0, "listener reply");
	close(client);
	wait_ok(child);
	std::string data;
	check(read_file(outside, data) && data == "secret", "outside file unchanged");
	std::filesystem::remove_all(base);
	puts("Landlock tests passed");
}
