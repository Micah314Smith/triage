
#include <array>
#include <bits/types/struct_iovec.h>
#include <limits>

#include <asm-generic/errno-base.h>
#include <asm/unistd_64.h>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>
#include <fcntl.h>

int main(int argc, const char* argv[])
{
    const auto pid = ::fork();

    if (pid == -1)
    {
        std::printf("Yo, you got an error while forking\n");
        std::exit(-1);
    }
    else if (pid == 0) 
    {
        // child
        ::ptrace(PTRACE_TRACEME);
        std::array<char, 1024u> x;
        std::strncpy(x.data(), "./docker", x.size());
        std::array< char*, 2u > dumb_args = { x.data(), nullptr };
        ::execvp(x.data(), dumb_args.data());
    }
    else 
    {
        // parente

        // Synce to exec
        ::waitpid(pid, nullptr, 0);


        char* proc_mem_filename;
        const auto status = asprintf(&proc_mem_filename, "/proc/%ld/mem", (long)pid);
        assert(-1 != status);

        const auto proc_mem_fd = ::open(proc_mem_filename, O_RDONLY);
        assert(-1 != proc_mem_fd);

        ::free(proc_mem_filename);

        const auto read_proc_str = [&](std::array< char, 1024u >& buf, __off_t user_addr)
        {
            const auto r = ::lseek(proc_mem_fd, user_addr, SEEK_SET);
            size_t buf_i = 0;
            while (true)
            {
                ::read(proc_mem_fd, buf.data()+buf_i, 1u);
                if (buf[buf_i] == 0)
                {
                    break;
                }
                buf_i += 1u;
            }
        };
        

        ::ptrace(PTRACE_SETOPTIONS, pid, 0, 
              PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXEC
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACEEXIT
        );

        while (true)
        {
            if (::ptrace(PTRACE_SYSCALL, pid) == -1)
            {
                std::printf("bad news\n");
            }
            if (::waitpid(pid, nullptr, 0) == -1)
            {
                std::printf("more bad news\n");
            }

            // Grab syscall regs
            ::user_regs_struct  u;
            if (::ptrace(PTRACE_GETREGS, pid, 0, &u) == -1)
            {
                std::printf("could not get regs\n");
            }

            const auto syscall = u.orig_rax;

            const auto syscall_is_mount = syscall == __NR_mount;
            if (syscall_is_mount)
            {
                std::printf("Got mount call!\n");

                const auto dev_name = u.rdi;
                const auto dir_name = u.rsi;
                const auto type = u.rdx;
                const auto flags = u.r10;
                const auto data = u.r8;

                std::array< char, 1024 > dev_name_str, dir_name_str, type_str, data_str;
                read_proc_str(dev_name_str, dev_name);
                read_proc_str(dir_name_str, dir_name);
                read_proc_str(type_str, type);
                read_proc_str(data_str, data);


                std::printf("Got args `%s`, `%s`, `%s`, `%s`\n", dev_name_str.data(), dir_name_str.data(), type_str.data(), data_str.data());
                

                // Modify to run non-existant call
                u.orig_rax = std::numeric_limits<decltype(u.orig_rax)>::max();
                ::ptrace(PTRACE_SETREGS, pid, 0, &u);
            }

            // Run syscall and stop on exit
            if (::ptrace(PTRACE_SYSCALL, pid) == -1)
            {
                std::printf("Could not run syscall\n");
            }
            if (::waitpid(pid, nullptr, 0) == -1)
            {
                std::printf("Really sad\n");
            }

            // Get syscall result
            if (::ptrace(PTRACE_GETREGS, pid, 0, &u) == -1)
            {
                if (errno == ESRCH)
                {
                    // The child exited
                    if (proc_mem_fd != -1)
                    {
                        ::close(proc_mem_fd);
                    }
                    std::printf("happy endings\n");
                    std::exit(0);
                }
                std::printf("Uber sad\n");
            }

            std::printf("The results are in: syscall %lld returned %lld\n", syscall, u.rax);

        }

    }

    // unreachable
    return 0;
}
