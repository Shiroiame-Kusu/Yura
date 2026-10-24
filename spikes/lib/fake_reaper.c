/*
 * Stands in for Steam's reaper, the one process Steam starts every game through.
 *
 *   reaper SteamLaunch AppId=<id> -- <command...>
 *
 * Compiled rather than scripted, so its command line reads exactly as Steam's does: an
 * interpreter would put its script's path in argv[1]. Like Steam's, it forks the game at once
 * and waits for it, which is the race a rule on Steam's launch has to win: a child forked
 * before the launch is placed starts outside the rule's group, with everything it runs.
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int i = 1;
    while (i < argc && strcmp(argv[i], "--") != 0)
    {
        i++;
    }

    if (i + 1 >= argc)
    {
        fprintf(stderr, "usage: reaper SteamLaunch AppId=<id> -- command...\n");
        return 2;
    }

    pid_t child = fork();
    if (child < 0)
    {
        perror("fork");
        return 1;
    }

    if (child == 0)
    {
        execvp(argv[i + 1], &argv[i + 1]);
        perror("execvp");
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0)
    {
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
