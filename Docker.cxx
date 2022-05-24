
#include <cstdio>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/stat.h>

#include <thread>

static void easy_thread()
{
    std::printf("Check this out!\n");
}


int main()
{
    auto my_thread = std::thread(easy_thread);
    const auto res = ::mount("tmpfs", "/mnt/dumb", "tmpfs", 0u, "size=1M,uid0,gid=0,mode=777");

    std::printf("Mount status: %d\n", res);

    my_thread.join();
    return 0;
}

