
#include <array>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>

#include <asm-generic/errno-base.h>
#include <asm/unistd_64.h>
#include <bits/types/struct_iovec.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include <unistd.h>
#include <fcntl.h>

enum class TraceState
{
    NONE,
    SIGNALLED,
    EXITED,
    SYSCALL,
    GROUP_STOP,
    SIGNAL_DELIVERY,
    RESTART // Need to restart the trace
};

/// Process state
struct PState
{
    TraceState ts;
    std::optional< long long unsigned > syscall_entrance;
    bool is_new;

    constexpr PState()
    : ts(TraceState::NONE)
    , syscall_entrance()
    , is_new(true)
    {}
};

// For our nice application code, don't use the macro because that is apparently
// not completely true; instead grab it from the system configuration upon program
// start.
// TODO: Think about doing things the sysconf way
// #ifdef PAGE_SIZE
// #   undef PAGE_SIZE
// #endif
// static const unsigned long PAGE_SIZE = ::sysconf(_SC_PAGESIZE);
// static const auto PAGE_MASK = PAGE_SIZE - 1u;

constexpr auto mmmm = PAGE_MASK;

static void 
process_vm_readv_cstr(pid_t pid, std::string& str, std::uintptr_t remote_str) __THROW
{
    std::string::value_type page_buf[PAGE_SIZE];
    static_assert(sizeof(std::string::value_type) == 1, "No like non-ascii");

    //       String Start
    //       V
    // c c c s s s | s s s s s s
    //             ^
    //             Page Boundary

    const auto local_io = ::iovec{ .iov_base=page_buf, .iov_len=PAGE_SIZE };
    
    std::uintptr_t remote_addr = (remote_str) & PAGE_MASK;
    std::uintptr_t page_offset = (remote_str) & (~PAGE_MASK);
    std::size_t n_needed = 0u;
    while (true)
    {
        const auto remote_io = ::iovec{ .iov_base=reinterpret_cast<void*>(remote_addr), .iov_len=PAGE_SIZE };

        process_vm_readv(pid, &local_io, 1u, &remote_io, 1u, 0u);

        auto n_valid = PAGE_SIZE - page_offset;
        const auto null_addr = reinterpret_cast<std::uintptr_t>(
            memchr(page_buf + page_offset, 0, n_valid));

        if (null_addr != 0)
        {
            // We found the last part, copy it and return
            n_valid = null_addr - (reinterpret_cast<std::uintptr_t>(page_buf) + page_offset);
        }

        const auto str_size = n_needed;
        n_needed += n_valid;
        str.resize(n_needed);
        // str.reserve(n_needed);
        std::memcpy(str.data() + str_size, page_buf + page_offset, n_valid);

        if (null_addr != 0)
        {
            break;
        }

        remote_addr += PAGE_SIZE;
        page_offset = 0u;
    }
}

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

        // This is the main PID of the child
        const auto root_pid = pid;
        std::unordered_map<pid_t, PState> pid2state;

        auto flog = std::fopen("log.txt", "wt");

        bool are_options_set = false;
        for (auto iter = 0u; iter < 1000; iter++)
        {
            // Wait for any PID to report it is in a stopped state
            unsigned int prime_status;
            auto prime_pid = ::waitpid(-1, reinterpret_cast<int*>(&prime_status), __WALL);
            auto prime_errno = errno;
            std::fprintf(flog,
                "[PID %8d] %08x (%d)\n", 
                prime_pid, prime_status, prime_errno);

            if (!are_options_set)
            {
                assert(prime_pid == root_pid);
                are_options_set = true;

                ::ptrace(PTRACE_SETOPTIONS, prime_pid, 0, 
                      PTRACE_O_TRACECLONE
                    | PTRACE_O_TRACEEXEC
                    | PTRACE_O_TRACEFORK
                    | PTRACE_O_TRACEVFORK
                    | PTRACE_O_TRACEEXIT
                    | PTRACE_O_TRACESYSGOOD
                );

                // suspect code here...
                ::ptrace(PTRACE_SYSCALL, prime_pid, 0, 0);
                continue;
            }

            if (prime_pid < 0)
            {
                // Check if all of our children have exited and if so, pat ourselve
                // on the back and mark completion
                if (prime_errno == ECHILD)
                {
                    std::printf("Happy Endings!\n");
                    std::exit(0);
                }
                std::printf("Well... that doesn't seem right\n");
            }
            else if (prime_pid == 0) 
            {
                std::printf("Nothing to wait on... what to do??\n");
            }
            else
            {
                auto& prime = pid2state[prime_pid];
                if (WIFSIGNALED(prime_status))
                {
                    prime.ts = TraceState::SIGNALLED;
                }
                else if (WIFEXITED(prime_status)) 
                {
                    prime.ts = TraceState::EXITED;
                }
                else
                {
                    assert(WIFSTOPPED(prime_status));
                    const auto sig = WSTOPSIG(prime_status);
                    const auto event = prime_status >> 16;

                    std::printf("Testing: %u %u\n", sig, event);
                    int prime_signal = 0;
                    switch (event)
                    {
                        case 0:
                        {
                            if (sig == SIGSTOP)
                            {
                                std::printf("Can't handle all the stops\n");
                                prime.ts = TraceState::NONE;
                            }
                            else if (sig == (SIGTRAP | 0x80))
                            {
                                prime.ts = TraceState::SYSCALL;
                            }
                            else
                            {
                                siginfo_t si;
                                const bool is_stopped = ::ptrace(PTRACE_GETSIGINFO,
                                    prime_pid,
                                    0,
                                    &si
                                ) < 0;
                                std::printf("Can't handle all these signals %d %d %d\n", si.si_signo, is_stopped, sig);

                                if (is_stopped)
                                {
                                    prime.ts = TraceState::GROUP_STOP;
                                }
                                else
                                {
                                    prime.ts = TraceState::SIGNAL_DELIVERY;
                                    prime_signal = sig; //si.si_signo;
                                }
                            }
                            break;
                        }
                        case PTRACE_EVENT_EXIT:
                        {
                            std::printf("Leaving so soon?\n");
                            break;
                        }
                        case PTRACE_EVENT_EXEC:
                        {
                            assert(false && "Exec not yet implemented");
                            break;
                        }
                        case PTRACE_EVENT_FORK: [[fallthrough]];
                        case PTRACE_EVENT_VFORK: [[fallthrough]];
                        case PTRACE_EVENT_VFORK_DONE: [[fallthrough]];
                        case PTRACE_EVENT_CLONE:
                        {
                            prime.ts = TraceState::NONE;
                            break;
                        }
                    }

                    std::printf("-> [%8d] %d\n", prime_pid, prime.ts);

                    if (prime.ts == TraceState::SYSCALL)
                    {
                        // Grab syscall regs
                        ::user_regs_struct  u;
                        if (::ptrace(PTRACE_GETREGS, prime_pid, 0, &u) == -1)
                        {
                            std::printf("could not get regs\n");
                        }
                        const auto syscall = u.orig_rax;

                        if (prime.syscall_entrance.has_value())
                        {
                            // Okay, so we are in the exit
                            if (syscall == prime.syscall_entrance.value())
                            {
                                // Joyous
                            }
                            else
                            {
                                std::fprintf(flog, 
                                    "[PID %8d] Syscall on begin and end didn't match! Before %llu, after %llu\n",
                                    prime_pid,
                                    prime.syscall_entrance.value(),
                                    syscall
                                );
                            }
                            prime.syscall_entrance.reset();
                            std::fprintf(flog, "[PID %8d] Syscall EXIT!!!! %llu\n", prime_pid, syscall);
                        }
                        else
                        {
                            // We are in the entrance to a syscall
                            std::fprintf(flog, "[PID %8d] Syscall ENTE!!!! %llu\n", prime_pid, syscall);
                            prime.syscall_entrance = syscall;

                            switch (syscall)
                            {
                                case SYS_mount:
                                {
                                    std::printf("Got mount call!\n");
                                    const auto dir_name_addr = u.rsi;
                                    std::string dir_name;
                                    process_vm_readv_cstr(prime_pid, dir_name, dir_name_addr);
                                    std::printf("WHHHHH: (%lu) %d %s\n", dir_name.size(), dir_name[0], dir_name.c_str());
                                    break;
                                }
                                default: { break; }
                            }
                        }
                    }

                    // TODO: Here is where we would manipulate syscalls

                    // And now, what to do about the trace
                    ::ptrace(PTRACE_SYSCALL, prime_pid, 0, prime_signal);
                }
            }

            // if (::ptrace(PTRACE_SYSCALL, pid) == -1)
            // {
            //     std::printf("bad news\n");
            // }

 


            // const auto syscall_is_mount = syscall == __NR_mount;
            // if (syscall_is_mount)
            // {
            //     std::printf("Got mount call!\n");

            //     const auto dev_name = u.rdi;
            //     const auto dir_name = u.rsi;
            //     const auto type = u.rdx;
            //     const auto flags = u.r10;
            //     const auto data = u.r8;

            //     std::array< char, 1024 > dev_name_str, dir_name_str, type_str, data_str;

            //     // std::printf("Got args `%s`, `%s`, `%s`, `%s`\n", dev_name_str.data(), dir_name_str.data(), type_str.data(), data_str.data());
                

            //     // Modify to run non-existant call
            //     u.orig_rax = std::numeric_limits<decltype(u.orig_rax)>::max();
            //     ::ptrace(PTRACE_SETREGS, pid, 0, &u);
            // }

            // // Run syscall and stop on exit
            // if (::ptrace(PTRACE_SYSCALL, pid) == -1)
            // {
            //     std::printf("Could not run syscall\n");
            // }
            // if (::waitpid(pid, nullptr, 0) == -1)
            // {
            //     std::printf("Really sad\n");
            // }

            // // Get syscall result
            // if (::ptrace(PTRACE_GETREGS, pid, 0, &u) == -1)
            // {
            //     if (errno == ESRCH)
            //     {
            //         std::printf("happy endings\n");
            //         std::exit(0);
            //     }
            //     std::printf("Uber sad\n");
            // }

            // std::printf("The results are in: syscall %lld returned %lld\n", syscall, u.rax);

        }

        std::fclose(flog);

    }

    // unreachable
    return 0;
}
